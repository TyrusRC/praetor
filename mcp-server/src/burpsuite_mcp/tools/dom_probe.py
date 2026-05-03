"""DOM-aware probe layer.

Sends a unique marker — optionally wrapped in a polyglot exploit syntax —
through URL fragment / query / referrer and captures which dangerous DOM
sinks it reaches. Closes the gap that pure HTTP-and-look-at-response
probing cannot detect:

- DOM-based XSS         (innerHTML / code-eval / document.write / Function)
- DOM open redirection  (location.assign / replace / href / window.open)
- Link manipulation     (href / src / action attribute set with marker)
- DOM data manipulation (textNode marker reflection without sink fire)
- CSPP                  (Object.prototype canary acquired marker OR any
                         non-standard own-prop appeared on Object.prototype)
- AngularJS CSTI        (ng-bind / ng-include text contains marker after
                         evaluation)

Polyglot variants rotated per source kind so the same source/sink pair
gets multiple exploit attempts:

- plain          : __SWMARKER__
- angular_csti   : {{__SWMARKER__}}              (AngularJS expression eval)
- vue_csti       : {{ __SWMARKER__ }}            (Vue mustache)
- handlebars     : {{= __SWMARKER__ }}
- proto_pollute  : __proto__[__SWMARKER__]=1     (merge-gadget canary)
- proto_constr   : constructor[prototype][__SWMARKER__]=1
- xss_svg        : <svg/onload=__SWMARKER__>
- xss_img        : <img src=x onerror=__SWMARKER__>
- url_break      : "><__SWMARKER__               (attribute breakout)

The init script always grep-s the BASE marker; the polyglot wrapper just
gives the application a chance to evaluate / mutate / pollute on the way.
"""

import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qsl

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.browser import _ensure_browser


_INIT_JS_PATH = Path(__file__).parent / "dom_probe_init.js"
_INIT_JS_CACHE: str | None = None


def _load_init_js() -> str:
    global _INIT_JS_CACHE
    if _INIT_JS_CACHE is None:
        _INIT_JS_CACHE = _INIT_JS_PATH.read_text()
    return _INIT_JS_CACHE


_SINK_TO_VULN_CLASS = {
    "innerHTML": ("dom_xss", "Marker reached innerHTML — DOM-based XSS sink"),
    "outerHTML": ("dom_xss", "Marker reached outerHTML — DOM-based XSS sink"),
    "document.write": ("dom_xss", "Marker reached document.write — DOM-based XSS sink"),
    "document.writeln": ("dom_xss", "Marker reached document.writeln — DOM-based XSS sink"),
    "eval": ("dom_xss", "Marker reached code-evaluation sink — DOM-based XSS / RCE"),
    "Function": ("dom_xss", "Marker reached Function() constructor — DOM-based XSS sink"),
    "setTimeout(string)": ("dom_xss", "Marker reached setTimeout(string) — DOM-based XSS sink"),
    "setInterval(string)": ("dom_xss", "Marker reached setInterval(string) — DOM-based XSS sink"),
    "$.fn.html": ("dom_xss", "Marker reached jQuery .html() — DOM-based XSS sink"),
    "location.assign": ("open_redirect_dom", "Marker controlled location.assign() — DOM open redirect"),
    "location.replace": ("open_redirect_dom", "Marker controlled location.replace() — DOM open redirect"),
    "location.href": ("open_redirect_dom", "Marker controlled location.href setter — DOM open redirect"),
    "window.open": ("open_redirect_dom", "Marker controlled window.open() URL — DOM open redirect"),
    "setAttribute(href)": ("link_manipulation", "Marker reached href via setAttribute — DOM link manipulation"),
    "setAttribute(src)": ("link_manipulation", "Marker reached src via setAttribute — DOM link manipulation"),
    "setAttribute(action)": ("link_manipulation", "Marker reached form action via setAttribute — link manipulation"),
    "setAttribute(formaction)": ("link_manipulation", "Marker reached formaction via setAttribute — link manipulation"),
    "postMessage": ("postmessage_leak", "Marker passed to postMessage — potential cross-frame leak"),
    "angular_ng_bind": ("client_side_template_injection", "Marker rendered inside ng-bind / ng-include — AngularJS CSTI"),
}


# Polyglot wrappers. Key = name; value = python format string with {marker} placeholder.
# Order matters — we test highest-signal first and short-circuit on the first hit
# per source kind.
_POLYGLOTS: dict[str, str] = {
    "plain":         "{marker}",
    "angular_csti":  "{{{{{marker}}}}}",                     # {{<marker>}} — Angular/Vue
    "handlebars":    "{{{{= {marker} }}}}",                  # Handlebars triple-stash
    "proto_pollute": "__proto__[{marker}]=1",                # CSPP merge gadget marker
    "proto_constr":  "constructor[prototype][{marker}]=1",   # CSPP via constructor
    "xss_svg":       "<svg/onload={marker}>",
    "xss_img":       "<img src=x onerror={marker}>",
    "url_break":     "\"><{marker}",
}


def _make_marker(suffix: str = "") -> str:
    seq = int(time.time() * 1000) % 100_000_000
    return f"swk{seq:x}{suffix}"


def _build_target_url(base_url: str, payload: str, source_param: str, source_kind: str) -> tuple[str, dict]:
    parsed = urlparse(base_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    fragment = parsed.fragment
    extra_headers: dict = {}

    if source_kind == "query":
        query[source_param] = payload
    elif source_kind == "fragment":
        fragment = payload
    elif source_kind == "fragment_kv":
        fragment = f"{source_param}={payload}"
    elif source_kind == "referrer":
        extra_headers["Referer"] = f"https://attacker.example/?{source_param}={payload}"
    else:
        raise ValueError(f"Unknown source_kind: {source_kind}")

    new_url = parsed._replace(
        query=urlencode(query, doseq=True),
        fragment=fragment,
    ).geturl()
    return new_url, extra_headers


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_dom_sinks(  # cost: medium
        url: str,
        source_param: str = "q",
        source_kinds: list[str] | None = None,
        polyglots: list[str] | None = None,
        wait_ms: int = 2500,
    ) -> str:
        """Inject a unique marker (optionally wrapped in a polyglot exploit
        payload) through query / fragment / referrer and capture which DOM
        sinks it reaches.

        Detects DOM-based XSS, DOM open-redirect, link manipulation, DOM
        data manipulation, client-side prototype pollution, and AngularJS
        client-side template injection.

        Args:
            url: Target URL (must already be in scope).
            source_param: Parameter name to inject the marker into
                (for query / fragment_kv / referrer kinds).
            source_kinds: Subset of ['query', 'fragment', 'fragment_kv', 'referrer'].
                Default: all four.
            polyglots: Subset of polyglot wrappers to rotate per source kind.
                Default: ['plain', 'angular_csti', 'proto_pollute', 'xss_svg'].
                Full list: plain, angular_csti, handlebars, proto_pollute,
                proto_constr, xss_svg, xss_img, url_break.
            wait_ms: How long to wait after navigation for async DOM mutations
                (default 2500ms).
        """
        from burpsuite_mcp import client as burp_client

        scope = await burp_client.check_scope(url)
        if "error" not in scope and not scope.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. configure_scope() first."

        kinds = source_kinds or ["query", "fragment", "fragment_kv", "referrer"]
        valid_kinds = {"query", "fragment", "fragment_kv", "referrer"}
        bad = [k for k in kinds if k not in valid_kinds]
        if bad:
            return f"Error: unknown source_kind(s) {bad}. Choose from {sorted(valid_kinds)}."

        active_polys = polyglots or ["plain", "angular_csti", "proto_pollute", "xss_svg"]
        bad_p = [p for p in active_polys if p not in _POLYGLOTS]
        if bad_p:
            return f"Error: unknown polyglot(s) {bad_p}. Choose from {sorted(_POLYGLOTS)}."

        try:
            init_template = _load_init_js()
        except OSError as e:
            return f"Error: could not load DOM init script ({e})"

        _, context, _ = await _ensure_browser()

        all_findings: list[dict] = []
        per_run_summary: list[str] = []

        for kind in kinds:
            for poly_name in active_polys:
                marker = _make_marker(suffix=kind[:1] + poly_name[:1])
                payload = _POLYGLOTS[poly_name].format(marker=marker)
                target_url, extra_headers = _build_target_url(url, payload, source_param, kind)
                init = init_template.replace("__SWMARKER__", marker)

                page = await context.new_page()
                try:
                    await page.add_init_script(init)
                    if extra_headers:
                        await page.set_extra_http_headers(extra_headers)
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                    except Exception as e:
                        per_run_summary.append(f"  [{kind}/{poly_name}] navigate failed: {str(e)[:120]}")
                        continue

                    try:
                        await page.mouse.move(100, 100)
                        await page.mouse.move(200, 200)
                        await page.mouse.down()
                        await page.mouse.up()
                    except Exception:
                        pass

                    await page.wait_for_timeout(wait_ms)

                    try:
                        scan = await page.evaluate("() => window.__sw_post_scan ? window.__sw_post_scan() : null")
                    except Exception as e:
                        per_run_summary.append(f"  [{kind}/{poly_name}] scan call failed: {str(e)[:120]}")
                        continue

                    if not scan:
                        per_run_summary.append(f"  [{kind}/{poly_name}] init script did not load")
                        continue

                    hits = scan.get("hits", []) or []
                    attr_hits = scan.get("attribute_marker_hits", []) or []
                    text_hits = scan.get("textnode_marker_hits", 0) or 0
                    pp_canary = scan.get("pp_canary")
                    pp_keys = scan.get("pp_polluted_keys", []) or []
                    rendered_marker = scan.get("rendered_html_marker", False)

                    for h in hits:
                        sink = h.get("sink", "?")
                        vclass, descr = _SINK_TO_VULN_CLASS.get(sink, ("dom_xss", f"Marker reached {sink}"))
                        all_findings.append({
                            "vuln_class": vclass,
                            "sink": sink,
                            "source_kind": kind,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": descr,
                            "value_excerpt": h.get("value_excerpt", ""),
                            "stack": h.get("stack", ""),
                            "tag": h.get("tag", ""),
                        })

                    for a in attr_hits:
                        all_findings.append({
                            "vuln_class": "link_manipulation",
                            "sink": f"<{a.get('tag','?').lower()} {a.get('attr','?')}>",
                            "source_kind": kind,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": f"Marker reflected into {a.get('attr', '?')} attribute of <{a.get('tag','?').lower()}> — DOM link manipulation",
                            "value_excerpt": a.get("value", "")[:200],
                        })

                    if text_hits > 0 and not any(h.get("sink") in ("innerHTML", "outerHTML", "document.write") for h in hits):
                        all_findings.append({
                            "vuln_class": "dom_data_manipulation",
                            "sink": "textnode",
                            "source_kind": kind,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": f"Marker written into {text_hits} text node(s) — DOM data manipulation (no executable sink, but content reflects user-controlled source)",
                        })

                    if isinstance(pp_canary, str) and marker in pp_canary:
                        all_findings.append({
                            "vuln_class": "client_side_prototype_pollution",
                            "sink": "Object.prototype.__sw_pp_canary__",
                            "source_kind": kind,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": "Marker reached Object.prototype via merge/extend gadget — CSPP",
                            "value_excerpt": str(pp_canary)[:200],
                        })

                    # Marker landed as an OWN PROPERTY of Object.prototype.
                    # That's the proto_pollute polyglot succeeding.
                    if marker in pp_keys:
                        all_findings.append({
                            "vuln_class": "client_side_prototype_pollution",
                            "sink": f"Object.prototype.{marker}",
                            "source_kind": kind,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": f"`__proto__[{marker}]=1` polyglot succeeded — Object.prototype acquired the marker key. Confirms CSPP merge-gadget.",
                        })

                    per_run_summary.append(
                        f"  [{kind}/{poly_name}] sinks={len(hits)} attr={len(attr_hits)} "
                        f"text={text_hits} pp_canary={'Y' if pp_canary else 'N'} "
                        f"pp_keys={len(pp_keys)} html={'Y' if rendered_marker else 'N'}"
                    )
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

        lines = [f"DOM probe: {url}"]
        lines.append(f"Source param: {source_param} | Kinds: {', '.join(kinds)} | Polyglots: {', '.join(active_polys)}")
        lines.append("")
        lines.extend(per_run_summary)
        lines.append("")
        if not all_findings:
            lines.append("No DOM sink reflections detected.")
            return "\n".join(lines)

        lines.append(f"FINDINGS ({len(all_findings)}):")
        grouped: dict[str, list[dict]] = {}
        for f in all_findings:
            grouped.setdefault(f["vuln_class"], []).append(f)
        for vc, fs in grouped.items():
            lines.append(f"\n--- {vc.upper()} ({len(fs)}) ---")
            for f in fs[:8]:
                lines.append(f"  sink={f['sink']}  source={f['source_kind']}({f['source_param']})  poly={f.get('polyglot','-')}")
                lines.append(f"    {f['description']}")
                ve = f.get("value_excerpt", "")
                if ve:
                    lines.append(f"    value: {ve[:160]}")
                tag = f.get("tag", "")
                if tag:
                    lines.append(f"    tag: <{tag.lower()}>")
            if len(fs) > 8:
                lines.append(f"  ... +{len(fs) - 8} more")

        lines.append("")
        lines.append("Verify each finding manually before save_finding — confirm the source is")
        lines.append("attacker-controllable (cross-origin / link-shared / fragment-craftable) and")
        lines.append("the sink isn't sanitised (Trusted Types / DOMPurify / framework escaping).")
        return "\n".join(lines)
