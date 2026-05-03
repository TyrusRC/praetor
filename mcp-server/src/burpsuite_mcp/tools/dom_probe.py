"""DOM-aware probe layer.

Sends a unique marker through URL fragment / query / referrer and captures
which dangerous DOM sinks the marker reaches. Closes the gap that pure
HTTP-and-look-at-response probing cannot detect:

- DOM-based XSS         (innerHTML / code-eval sinks / document.write / Function)
- Open redirection      (location / location.href assignment)
- Link manipulation     (href / src / action attribute set with marker)
- DOM data manipulation (textContent / innerText set with marker)
- CSPP / proto-pollution (Object.prototype write detected via canary)

Each tool call:
1. Generates a unique marker
2. Lazily reuses the shared Playwright browser from browser.py
3. Creates a NEW page with an init script (runs BEFORE any target script)
   that wraps the dangerous sinks and pushes hits into window.__sw_sink_hits
4. Navigates with the marker injected per the requested source kind
5. Waits ~2.5s for async renders, reads window.__sw_sink_hits
6. Returns one finding per (sink, source_kind) combo

Out of scope for this first cut: form submission, click-based DOM XSS,
postMessage cross-frame chains, multi-step prototype pollution gadget
detection.
"""

import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qsl

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.browser import _ensure_browser


_INIT_JS_PATH = Path(__file__).parent / "dom_probe_init.js"
_INIT_JS_CACHE: str | None = None


def _load_init_js() -> str:
    """Read and cache the sink-monitor init script."""
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
    "location.assign": ("open_redirect_dom", "Marker controlled location.assign() — DOM-based open redirect"),
    "location.replace": ("open_redirect_dom", "Marker controlled location.replace() — DOM-based open redirect"),
    "location.href": ("open_redirect_dom", "Marker controlled location.href setter — DOM-based open redirect"),
    "window.open": ("open_redirect_dom", "Marker controlled window.open() URL — DOM-based open redirect"),
    "setAttribute(href)": ("link_manipulation", "Marker reached href via setAttribute — DOM link manipulation"),
    "setAttribute(src)": ("link_manipulation", "Marker reached src via setAttribute — DOM link manipulation"),
    "setAttribute(action)": ("link_manipulation", "Marker reached form action via setAttribute — link manipulation"),
    "setAttribute(formaction)": ("link_manipulation", "Marker reached formaction via setAttribute — link manipulation"),
    "postMessage": ("postmessage_leak", "Marker passed to postMessage — potential cross-frame leak"),
}


def _make_marker(suffix: str = "") -> str:
    """Generate a unique marker. Lowercase hex of ms — short and grep-able."""
    seq = int(time.time() * 1000) % 100_000_000
    return f"swk{seq:x}{suffix}"


def _build_target_url(base_url: str, marker: str, source_param: str, source_kind: str) -> tuple[str, dict]:
    """Construct the target URL with the marker in the requested source location.

    Returns (url, extra_headers) where extra_headers may set Referer.
    """
    parsed = urlparse(base_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    fragment = parsed.fragment
    extra_headers: dict = {}

    if source_kind == "query":
        query[source_param] = marker
    elif source_kind == "fragment":
        fragment = marker
    elif source_kind == "fragment_kv":
        fragment = f"{source_param}={marker}"
    elif source_kind == "referrer":
        extra_headers["Referer"] = f"https://attacker.example/?{source_param}={marker}"
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
        wait_ms: int = 2500,
    ) -> str:
        """Inject a unique marker through query / fragment / referrer and capture
        which DOM sinks it reached. Detects DOM-based XSS, DOM open-redirect,
        link manipulation, DOM data manipulation, CSPP — vuln classes that
        HTTP-and-look-at-response probing cannot see.

        Args:
            url: Target URL (must already be in scope).
            source_param: Parameter name to inject the marker into (for query / fragment_kv / referrer kinds).
            source_kinds: Subset of ['query', 'fragment', 'fragment_kv', 'referrer']. Default: all four.
            wait_ms: How long to wait after navigation for async DOM mutations (default 2500ms).
        """
        from burpsuite_mcp import client as burp_client

        scope = await burp_client.check_scope(url)
        if "error" not in scope and not scope.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. configure_scope() first."

        kinds = source_kinds or ["query", "fragment", "fragment_kv", "referrer"]
        valid = {"query", "fragment", "fragment_kv", "referrer"}
        bad = [k for k in kinds if k not in valid]
        if bad:
            return f"Error: unknown source_kind(s) {bad}. Choose from {sorted(valid)}."

        try:
            init_template = _load_init_js()
        except OSError as e:
            return f"Error: could not load DOM init script ({e})"

        _, context, _ = await _ensure_browser()

        all_findings: list[dict] = []
        per_kind_summary: list[str] = []

        for kind in kinds:
            marker = _make_marker(suffix=kind[:1])
            target_url, extra_headers = _build_target_url(url, marker, source_param, kind)
            init = init_template.replace("__SWMARKER__", marker)

            page = await context.new_page()
            try:
                await page.add_init_script(init)
                if extra_headers:
                    await page.set_extra_http_headers(extra_headers)
                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                except Exception as e:
                    per_kind_summary.append(f"  [{kind}] navigate failed: {str(e)[:120]}")
                    continue

                # Trigger common interaction events that DOM-XSS handlers wait for.
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
                    per_kind_summary.append(f"  [{kind}] scan call failed: {str(e)[:120]}")
                    continue

                if not scan:
                    per_kind_summary.append(f"  [{kind}] init script did not load")
                    continue

                hits = scan.get("hits", []) or []
                attr_hits = scan.get("attribute_marker_hits", []) or []
                text_hits = scan.get("textnode_marker_hits", 0) or 0
                pp_canary = scan.get("pp_canary")
                rendered_marker = scan.get("rendered_html_marker", False)

                for h in hits:
                    sink = h.get("sink", "?")
                    vclass, descr = _SINK_TO_VULN_CLASS.get(sink, ("dom_xss", f"Marker reached {sink}"))
                    all_findings.append({
                        "vuln_class": vclass,
                        "sink": sink,
                        "source_kind": kind,
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
                        "source_param": source_param if kind != "fragment" else "(fragment)",
                        "marker": marker,
                        "description": f"Marker reflected into {a.get('attr', '?')} attribute of <{a.get('tag','?').lower()}> — DOM link manipulation",
                        "value_excerpt": a.get("value", "")[:200],
                    })

                # DOM data manipulation: marker hit text nodes WITHOUT touching
                # an executable sink. Different finding class.
                if text_hits > 0 and not any(h.get("sink") in ("innerHTML", "outerHTML", "document.write") for h in hits):
                    all_findings.append({
                        "vuln_class": "dom_data_manipulation",
                        "sink": "textnode",
                        "source_kind": kind,
                        "source_param": source_param if kind != "fragment" else "(fragment)",
                        "marker": marker,
                        "description": f"Marker written into {text_hits} text node(s) — DOM data manipulation (no executable sink, but content reflects user-controlled source)",
                    })

                # CSPP: Object.prototype canary acquired the marker
                if isinstance(pp_canary, str) and marker in pp_canary:
                    all_findings.append({
                        "vuln_class": "client_side_prototype_pollution",
                        "sink": "Object.prototype.__sw_pp_canary__",
                        "source_kind": kind,
                        "source_param": source_param if kind != "fragment" else "(fragment)",
                        "marker": marker,
                        "description": "Marker reached Object.prototype via merge/extend gadget — CSPP",
                        "value_excerpt": str(pp_canary)[:200],
                    })

                per_kind_summary.append(
                    f"  [{kind}] sink hits={len(hits)} attr={len(attr_hits)} "
                    f"text={text_hits} pp={'yes' if pp_canary else 'no'} html_marker={'yes' if rendered_marker else 'no'}"
                )
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

        lines = [f"DOM probe: {url}"]
        lines.append(f"Source param: {source_param} | Source kinds tested: {', '.join(kinds)}")
        lines.append("")
        lines.extend(per_kind_summary)
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
                lines.append(f"  sink={f['sink']}  source={f['source_kind']}({f['source_param']})")
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
        lines.append("Verify each finding manually before save_finding — check that the source is")
        lines.append("attacker-controllable (cross-origin / link-shared / fragment) and the sink")
        lines.append("isn't sanitized (Trusted Types / DOMPurify / framework escaping).")
        return "\n".join(lines)
