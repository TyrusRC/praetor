"""DOM-aware probe layer.

Sends a unique marker — optionally wrapped in a polyglot exploit syntax
and embedded in a custom URL-shape — through query / fragment / referrer
and captures which DOM sinks the marker reaches. Designed to surface
the vuln classes pure HTTP-and-look-at-response probing cannot detect:

- DOM-based XSS         (innerHTML / code-eval / document.write / Function)
- DOM open redirection  (location.assign / replace / href / window.open)
- Link manipulation     (href / src / action attribute set with marker)
- DOM data manipulation (textNode marker reflection without sink fire)
- CSPP                  (Object.prototype canary OR new own-prop appeared)
- AngularJS CSTI        (ng-bind / ng-include text contains marker)

Source kinds:

- query         ?<source_param>=<payload>
- fragment      #<payload>
- fragment_kv   #<source_param>=<payload>
- fragment_shapes  several router patterns (see _FRAGMENT_SHAPES)
- referrer      Referer: <attacker>?<source_param>=<payload>

Polyglot wrappers are rotated per source kind so the same source/sink
pair gets multiple chances to trigger framework evaluation, DOM
injection, or prototype pollution.

Iteration 3: post-navigation in-app click-crawl. After the initial
navigation we click up to N visible same-origin anchors (skipping
logout / delete / signout), waiting wait_ms between clicks. SPAs that
render their content from a fragment-driven router only fire their
DOM sinks after a navigation event — not just the first goto.
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
    "script.src": ("dom_xss", "Marker reached HTMLScriptElement.src setter — DOM XSS via dynamic script load"),
    "appendChild(<script>)": ("dom_xss", "Marker reached <script> appendChild — DOM XSS via dynamic script load"),
    "insertBefore(<script>)": ("dom_xss", "Marker reached <script> insertBefore — DOM XSS via dynamic script load"),
    "replaceChild(<script>)": ("dom_xss", "Marker reached <script> replaceChild — DOM XSS via dynamic script load"),
    "appendChild(<iframe>)": ("link_manipulation", "Marker reached <iframe> appendChild — link manipulation / clickjacking"),
    "postMessage": ("postmessage_leak", "Marker passed to postMessage — potential cross-frame leak"),
    "angular_ng_bind": ("client_side_template_injection", "Marker rendered inside ng-bind / ng-include — AngularJS CSTI"),
}


# Polyglot exploit wrappers. Key = name; value = python format string with {marker}.
_POLYGLOTS: dict[str, str] = {
    "plain":         "{marker}",
    "angular_csti":  "{{{{{marker}}}}}",                     # {{<marker>}}
    "handlebars":    "{{{{= {marker} }}}}",                  # Handlebars triple-stash
    "proto_pollute": "__proto__[{marker}]=1",                # CSPP merge-gadget marker
    "proto_constr":  "constructor[prototype][{marker}]=1",   # CSPP via constructor
    "xss_svg":       "<svg/onload={marker}>",
    "xss_img":       "<img src=x onerror={marker}>",
    "url_break":     "\"><{marker}",
}


# CSPP "known-key" gadgets: pollute a real, app-used Object.prototype key
# (e.g. transport_url for searchLogger.js) with the marker as VALUE, then
# detect the marker arriving at any sink. Unlike `proto_pollute`, the
# polluted key is one the application code is expected to read.
_CSPP_DEFAULT_KEYS = (
    "transport_url",   # gnj searchLogger.js
    "src",
    "url",
    "html",
    "redirect_uri",
    "redirectUri",
    "next",
    "callback",
    "action",
    "include",
    "template",
)


# Fragment-shape variants — many SPAs use the URL fragment as a router
# input. The same payload has very different chances of reaching a sink
# depending on whether it's bare, after a `?` inside the fragment, after
# a slash, or shaped like a hash-route.
_FRAGMENT_SHAPES: dict[str, str] = {
    "bare":          "{payload}",
    "param":         "{param}={payload}",
    "amp_param":     "&{param}={payload}",
    "qs_in_hash":    "?{param}={payload}",
    "hash_route":    "/{payload}",
    "hash_route_kv": "/{param}/{payload}",
    "hashbang":      "!{payload}",
    "hashbang_kv":   "!/{param}/{payload}",
}


def _make_marker(suffix: str = "") -> str:
    seq = int(time.time() * 1000) % 100_000_000
    return f"swk{seq:x}{suffix}"


def _build_target_url(
    base_url: str,
    payload: str,
    source_param: str,
    source_kind: str,
    fragment_shape: str = "bare",
) -> tuple[str, dict]:
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
    elif source_kind == "fragment_shapes":
        shape = _FRAGMENT_SHAPES.get(fragment_shape, "{payload}")
        fragment = shape.format(param=source_param, payload=payload)
    elif source_kind == "referrer":
        extra_headers["Referer"] = f"https://attacker.example/?{source_param}={payload}"
    else:
        raise ValueError(f"Unknown source_kind: {source_kind}")

    new_url = parsed._replace(
        query=urlencode(query, doseq=True),
        fragment=fragment,
    ).geturl()
    return new_url, extra_headers


_DESTRUCTIVE_HREFS = ("/logout", "/signout", "/delete", "/remove", "/cancel")


async def _click_crawl(page, max_clicks: int = 4, wait_each_ms: int = 1500) -> None:
    """Click up to N visible same-origin anchors, waiting between each.
    Skips destructive links. Best-effort — stays defensive on stale DOM."""
    try:
        same_origin = await page.evaluate(
            """() => {
                const out = [];
                const origin = location.origin;
                document.querySelectorAll('a[href]').forEach(a => {
                    try {
                        const href = a.href;
                        if (!href || !href.startsWith(origin)) return;
                        const txt = (a.textContent || '').trim().slice(0, 40);
                        if (a.offsetParent === null) return;  // not visible
                        out.push(href);
                    } catch (e) {}
                });
                // De-dupe, keep first 10
                return Array.from(new Set(out)).slice(0, 10);
            }"""
        )
    except Exception:
        return

    if not same_origin:
        return

    candidates = [
        h for h in same_origin
        if not any(d in h.lower() for d in _DESTRUCTIVE_HREFS)
    ][:max_clicks]

    for href in candidates:
        try:
            await page.goto(href, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(wait_each_ms)
        except Exception:
            continue


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_dom_sinks(  # cost: medium
        url: str,
        source_param: str = "q",
        source_kinds: list[str] | None = None,
        polyglots: list[str] | None = None,
        fragment_shapes: list[str] | None = None,
        cspp_known_keys: list[str] | None = None,
        wait_ms: int = 2500,
        click_crawl: bool = True,
        max_clicks: int = 3,
    ) -> str:
        """Inject a unique marker (optionally wrapped in a polyglot exploit
        payload) through query / fragment / referrer and capture which DOM
        sinks it reaches. Detects DOM-based XSS, DOM open-redirect, link
        manipulation, DOM data manipulation, CSPP, AngularJS CSTI.

        Args:
            url: Target URL (must already be in scope).
            source_param: Parameter name to inject the marker into (for
                query / fragment_kv / fragment_shapes / referrer kinds).
            source_kinds: Subset of ['query', 'fragment', 'fragment_kv',
                'fragment_shapes', 'referrer']. Default: all five.
            polyglots: Subset of polyglot wrappers. Default:
                ['plain', 'angular_csti', 'proto_pollute', 'xss_svg'].
                Full list: plain, angular_csti, handlebars, proto_pollute,
                proto_constr, xss_svg, xss_img, url_break.
            fragment_shapes: When source_kinds includes 'fragment_shapes',
                which router patterns to test. Default: all of bare, param,
                qs_in_hash, hash_route, hash_route_kv, hashbang_kv.
            cspp_known_keys: List of Object.prototype keys to attempt to
                pollute via `?__proto__[<key>]=<marker>`. The marker is
                the VALUE, so any sink that later reads that key (e.g.
                `script.src = config.transport_url`) flags as DOM XSS via
                CSPP. Default: transport_url, src, url, html, redirect_uri,
                redirectUri, next, callback, action, include, template.
                Pass [] to disable.
            wait_ms: How long to wait after navigation for async DOM
                mutations (default 2500ms).
            click_crawl: After the initial navigation, click up to
                `max_clicks` visible same-origin anchors so SPA routers
                that only fire DOM sinks after a navigation event get
                a chance to trigger. Default True.
            max_clicks: Cap on click_crawl follow-up navigations. Default 3.
        """
        from burpsuite_mcp import client as burp_client

        scope = await burp_client.check_scope(url)
        if "error" not in scope and not scope.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. configure_scope() first."

        kinds = source_kinds or ["query", "fragment", "fragment_kv", "fragment_shapes", "referrer"]
        valid_kinds = {"query", "fragment", "fragment_kv", "fragment_shapes", "referrer"}
        bad = [k for k in kinds if k not in valid_kinds]
        if bad:
            return f"Error: unknown source_kind(s) {bad}. Choose from {sorted(valid_kinds)}."

        active_polys = polyglots or ["plain", "angular_csti", "proto_pollute", "xss_svg"]
        bad_p = [p for p in active_polys if p not in _POLYGLOTS]
        if bad_p:
            return f"Error: unknown polyglot(s) {bad_p}. Choose from {sorted(_POLYGLOTS)}."

        active_shapes = fragment_shapes or [
            "bare", "param", "qs_in_hash", "hash_route", "hash_route_kv", "hashbang_kv",
        ]
        bad_s = [s for s in active_shapes if s not in _FRAGMENT_SHAPES]
        if bad_s:
            return f"Error: unknown fragment_shape(s) {bad_s}. Choose from {sorted(_FRAGMENT_SHAPES)}."

        if cspp_known_keys is None:
            active_cspp_keys = list(_CSPP_DEFAULT_KEYS)
        else:
            active_cspp_keys = [str(k) for k in cspp_known_keys if isinstance(k, str) and k]

        try:
            init_template = _load_init_js()
        except OSError as e:
            return f"Error: could not load DOM init script ({e})"

        _, context, _ = await _ensure_browser()

        all_findings: list[dict] = []
        per_run_summary: list[str] = []

        # Build the (kind, shape) tuples to iterate. fragment_shapes expands
        # into one entry per shape; other kinds appear once with shape=None.
        run_specs: list[tuple[str, str | None]] = []
        for kind in kinds:
            if kind == "fragment_shapes":
                for shape in active_shapes:
                    run_specs.append((kind, shape))
            else:
                run_specs.append((kind, None))

        for kind, shape in run_specs:
            for poly_name in active_polys:
                shape_tag = (shape or "")[:3]
                marker = _make_marker(suffix=f"{kind[:1]}{poly_name[:1]}{shape_tag}")
                payload = _POLYGLOTS[poly_name].format(marker=marker)
                target_url, extra_headers = _build_target_url(
                    url, payload, source_param, kind, shape or "bare",
                )
                init = init_template.replace("__SWMARKER__", marker)

                page = await context.new_page()
                try:
                    await page.add_init_script(init)
                    if extra_headers:
                        await page.set_extra_http_headers(extra_headers)
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                    except Exception as e:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] navigate failed: {str(e)[:120]}"
                        )
                        continue

                    try:
                        await page.mouse.move(100, 100)
                        await page.mouse.move(200, 200)
                        await page.mouse.down()
                        await page.mouse.up()
                    except Exception:
                        pass

                    await page.wait_for_timeout(wait_ms)

                    # In-app click-crawl: SPA routers often only fire their
                    # DOM-side template/render sinks after a navigation event.
                    # The initial goto sets the URL, but the JS routing code
                    # that consumes the fragment may not run until a click
                    # triggers it.
                    if click_crawl:
                        await _click_crawl(page, max_clicks=max_clicks, wait_each_ms=wait_ms // 2 or 800)

                    try:
                        scan = await page.evaluate(
                            "() => window.__sw_post_scan ? window.__sw_post_scan() : null"
                        )
                    except Exception as e:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] scan call failed: {str(e)[:120]}"
                        )
                        continue

                    if not scan:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] init script did not load"
                        )
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
                            "fragment_shape": shape,
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
                            "fragment_shape": shape,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": f"Marker reflected into {a.get('attr', '?')} attribute of <{a.get('tag','?').lower()}> — DOM link manipulation",
                            "value_excerpt": a.get("value", "")[:200],
                        })

                    if text_hits > 0 and not any(
                        h.get("sink") in ("innerHTML", "outerHTML", "document.write") for h in hits
                    ):
                        all_findings.append({
                            "vuln_class": "dom_data_manipulation",
                            "sink": "textnode",
                            "source_kind": kind,
                            "fragment_shape": shape,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": (
                                f"Marker written into {text_hits} text node(s) — DOM data "
                                f"manipulation (no executable sink, but content reflects "
                                f"user-controlled source)"
                            ),
                        })

                    if isinstance(pp_canary, str) and marker in pp_canary:
                        all_findings.append({
                            "vuln_class": "client_side_prototype_pollution",
                            "sink": "Object.prototype.__sw_pp_canary__",
                            "source_kind": kind,
                            "fragment_shape": shape,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": "Marker reached Object.prototype via merge/extend gadget — CSPP",
                            "value_excerpt": str(pp_canary)[:200],
                        })

                    if marker in pp_keys:
                        all_findings.append({
                            "vuln_class": "client_side_prototype_pollution",
                            "sink": f"Object.prototype.{marker}",
                            "source_kind": kind,
                            "fragment_shape": shape,
                            "polyglot": poly_name,
                            "source_param": source_param if kind != "fragment" else "(fragment)",
                            "marker": marker,
                            "description": (
                                f"`__proto__[{marker}]=1` polyglot succeeded — "
                                f"Object.prototype acquired the marker key. Confirms CSPP merge-gadget."
                            ),
                        })

                    per_run_summary.append(
                        f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] "
                        f"sinks={len(hits)} attr={len(attr_hits)} text={text_hits} "
                        f"pp_canary={'Y' if pp_canary else 'N'} pp_keys={len(pp_keys)} "
                        f"html={'Y' if rendered_marker else 'N'}"
                    )
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

        # CSPP known-key pass: pollute Object.prototype.<key> with the marker
        # as VALUE. Detection: marker showed up at any sink, or
        # Object.prototype[<key>] === marker post-scan.
        for ck in active_cspp_keys:
            marker = _make_marker(suffix=f"c{ck[:4]}")
            payload_qs = f"__proto__[{ck}]=" + marker
            parsed = urlparse(url)
            sep = "&" if parsed.query else "?"
            target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{('?' + parsed.query) if parsed.query else ''}{sep}__proto__[{ck}]={marker}"
            if parsed.fragment:
                target_url += f"#{parsed.fragment}"
            init = init_template.replace("__SWMARKER__", marker)
            page = await context.new_page()
            try:
                await page.add_init_script(init)
                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                except Exception as e:
                    per_run_summary.append(
                        f"  [cspp_known_key/{ck}] navigate failed: {str(e)[:120]}"
                    )
                    continue
                await page.wait_for_timeout(wait_ms)
                if click_crawl:
                    await _click_crawl(page, max_clicks=max_clicks, wait_each_ms=wait_ms // 2 or 800)

                try:
                    proto_val = await page.evaluate(
                        "(k) => { try { return Object.prototype[k]; } catch(e) { return null; } }",
                        ck,
                    )
                except Exception:
                    proto_val = None
                try:
                    scan = await page.evaluate(
                        "() => window.__sw_post_scan ? window.__sw_post_scan() : null"
                    )
                except Exception:
                    scan = None

                hits = (scan or {}).get("hits", []) or []
                attr_hits = (scan or {}).get("attribute_marker_hits", []) or []
                polluted = isinstance(proto_val, str) and marker in proto_val

                if polluted:
                    all_findings.append({
                        "vuln_class": "client_side_prototype_pollution",
                        "sink": f"Object.prototype.{ck}",
                        "source_kind": "query",
                        "fragment_shape": None,
                        "polyglot": "cspp_known_key",
                        "source_param": f"__proto__[{ck}]",
                        "marker": marker,
                        "description": (
                            f"`?__proto__[{ck}]=...` polluted Object.prototype.{ck} "
                            f"with the marker. App-used key — direct gadget for any "
                            f"sink that reads {ck} from a config object."
                        ),
                        "value_excerpt": str(proto_val)[:200],
                    })

                for h in hits:
                    sink = h.get("sink", "?")
                    vclass, descr = _SINK_TO_VULN_CLASS.get(sink, ("dom_xss", f"Marker reached {sink}"))
                    chain_note = (
                        f" (CSPP→sink chain: __proto__[{ck}] populated, then {sink} read it)"
                        if polluted else f" (CSPP attempt for key={ck})"
                    )
                    all_findings.append({
                        "vuln_class": vclass,
                        "sink": sink,
                        "source_kind": "query",
                        "fragment_shape": None,
                        "polyglot": f"cspp_known_key[{ck}]",
                        "source_param": f"__proto__[{ck}]",
                        "marker": marker,
                        "description": descr + chain_note,
                        "value_excerpt": h.get("value_excerpt", ""),
                        "stack": h.get("stack", ""),
                        "tag": h.get("tag", ""),
                    })

                for a in attr_hits:
                    all_findings.append({
                        "vuln_class": "link_manipulation",
                        "sink": f"<{a.get('tag','?').lower()} {a.get('attr','?')}>",
                        "source_kind": "query",
                        "fragment_shape": None,
                        "polyglot": f"cspp_known_key[{ck}]",
                        "source_param": f"__proto__[{ck}]",
                        "marker": marker,
                        "description": (
                            f"CSPP→link chain: marker reflected into "
                            f"{a.get('attr', '?')} of <{a.get('tag','?').lower()}> after "
                            f"polluting Object.prototype.{ck}"
                        ),
                        "value_excerpt": a.get("value", "")[:200],
                    })

                per_run_summary.append(
                    f"  [cspp_known_key/{ck}] sinks={len(hits)} attr={len(attr_hits)} "
                    f"polluted={'Y' if polluted else 'N'}"
                )
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

        lines = [f"DOM probe: {url}"]
        lines.append(
            f"Source param: {source_param} | Kinds: {', '.join(kinds)} | "
            f"Polyglots: {', '.join(active_polys)}"
            + (f" | Frag shapes: {', '.join(active_shapes)}" if "fragment_shapes" in kinds else "")
            + (f" | CSPP keys: {len(active_cspp_keys)}" if active_cspp_keys else "")
            + (f" | click_crawl=on (max {max_clicks})" if click_crawl else " | click_crawl=off")
        )
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
                shape = f.get("fragment_shape")
                shape_str = f"/{shape}" if shape else ""
                lines.append(
                    f"  sink={f['sink']}  source={f['source_kind']}{shape_str}({f['source_param']})  "
                    f"poly={f.get('polyglot','-')}"
                )
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
        lines.append(
            "Verify each finding manually before save_finding — confirm the source is "
            "attacker-controllable (cross-origin / link-shared / fragment-craftable) and "
            "the sink isn't sanitised (Trusted Types / DOMPurify / framework escaping)."
        )
        return "\n".join(lines)
