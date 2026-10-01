"""In-browser IAST: passive DOM-sink instrumentation + source→sink correlation.

PTK-parity for the in-browser interactive-analysis model. `browser_iast_enable`
injects the hook shim (see _iast_js.IAST_SHIM) at document-start for every page
in the context — so as the crawler / operator drives the app, calls to the
dangerous DOM sinks (eval, innerHTML, document.write, insertAdjacentHTML,
setAttribute, string timers, location.assign/replace, window.open) and incoming
postMessage data are recorded passively. `browser_iast` reads them back, tagging
each hit with any taint SOURCE (location.hash/search/href, referrer, window.name,
cookie) that appears in the sink value — the DOM-XSS lead.

Enable BEFORE navigating: add_init_script runs on the NEXT navigation, so the
flow is browser_iast_enable() -> browser_crawl/navigate/interact -> browser_iast().
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ._iast_js import IAST_SHIM
from ._lifecycle import _ensure_browser


def _fmt(records: list, source_only: bool) -> str:
    if not isinstance(records, list):
        return "browser_iast: unexpected buffer shape (instrumentation may not be enabled)."
    hits = [r for r in records if isinstance(r, dict)]
    if source_only:
        hits = [r for r in hits if r.get("sources")]
    if not hits:
        base = "no sink hits with a correlated source yet" if source_only else "no DOM-sink hits recorded yet"
        return (f"browser_iast: {base}. Did you call browser_iast_enable() BEFORE "
                "navigating, then drive the app (crawl / interact)?")
    tainted = [r for r in hits if r.get("sources")]
    lines = [f"IAST: {len(hits)} sink hit(s), {len(tainted)} with a correlated source:"]
    for r in hits[:80]:
        src = r.get("sources") or []
        tag = f"  <= {', '.join(src)}" if src else ""
        flag = "[TAINTED] " if src else ""
        lines.append(f"  {flag}{r.get('sink','?')}: {str(r.get('value',''))[:160]!r}{tag}")
        if src:
            lines.append(f"      at {r.get('url','?')}")
    if tainted:
        lines.append("")
        lines.append("[TAINTED] = a taint source appears in the sink value (substring "
                     "heuristic) — verify as DOM XSS / open redirect with probe_xss_executed "
                     "or test_dom_sinks.")
    return "\n".join(lines)


def register(mcp: FastMCP):

    @mcp.tool()
    async def browser_iast_enable() -> str:
        """Turn on passive in-browser IAST (DOM-sink + source→sink instrumentation).

        Injects a hook shim at document-start for every page in the browser
        context. Call this BEFORE browser_crawl / browser_navigate / interaction:
        the shim runs on the NEXT navigation and records every dangerous-sink call
        (eval, innerHTML/outerHTML, document.write, insertAdjacentHTML,
        setAttribute, string setTimeout/setInterval, location.assign/replace,
        window.open) plus incoming postMessage data, tagging hits whose value
        contains a taint source (location.hash/search/href, referrer, window.name,
        cookie). Read results with browser_iast(). Source correlation is a
        substring heuristic, not full taint propagation.
        """
        browser, context, page = await _ensure_browser()
        try:
            await context.add_init_script(IAST_SHIM)   # future pages / navigations
        except Exception as e:  # noqa: BLE001
            return f"Error installing IAST init script: {e}"
        # Also hook the already-loaded current page (forward-only — sinks that
        # already fired before now are not retroactively captured).
        try:
            await page.evaluate(IAST_SHIM)
        except Exception:
            pass
        return ("IAST enabled. Hooks install on the next navigation for all pages "
                "in this context (and on the current page now). Flow: "
                "browser_navigate/crawl/interact -> browser_iast(). "
                "Tip: drive the target's hash/query (e.g. #<marker>) to surface "
                "source->sink correlations.")

    @mcp.tool()
    async def browser_iast(clear: bool = False, source_only: bool = False) -> str:
        """Read recorded DOM-sink hits (enable with browser_iast_enable first).

        Args:
            clear: reset the in-page buffer after reading (default False).
            source_only: show only hits whose value contains a taint source —
                the DOM-XSS leads (default False = all sink hits).
        """
        _, _, page = await _ensure_browser()
        try:
            records = await page.evaluate("() => (window.__praetor_iast || [])")
        except Exception as e:  # noqa: BLE001
            return f"Error reading IAST buffer: {e}"
        out = _fmt(records, source_only)
        if clear:
            try:
                await page.evaluate("() => { window.__praetor_iast = []; }")
            except Exception:
                pass
        # keep the raw buffer available to an agent that wants to post-process
        if isinstance(records, list) and records:
            out += "\n\n(raw: " + json.dumps(records[:40], default=str)[:1500] + ")"
        return out
