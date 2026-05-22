"""Stealth CloakBrowser lifecycle: launch, reuse, close.

State is module-global so a navigate -> click -> screenshot sequence reuses
the same browser/context/page. The lock is created lazily inside the event
loop because FastMCP creates its own loop on first tool call.
"""

import asyncio

from burpsuite_mcp.config import BURP_PROXY_HOST, BURP_PROXY_PORT

_browser = None
_context = None
_page = None
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def _ensure_browser():
    """Launch browser if not already running. Returns (browser, context, page).

    CloakBrowser handles the stealth layer at the binary level — no manual
    init scripts, no UA spoof, no `--disable-blink-features=AutomationControlled`
    flag (the binary patches that flag's underlying detection vectors directly).
    """
    global _browser, _context, _page

    async with _get_lock():
        if _browser and _browser.is_connected():
            if _context is None:
                _page = None
            elif _page and not _page.is_closed():
                return _browser, _context, _page
            else:
                _page = None
            if _context is not None:
                _page = await _context.new_page()
                return _browser, _context, _page

        try:
            from cloakbrowser import launch_async
        except ImportError:
            raise RuntimeError(
                "CloakBrowser not installed. Run: uv pip install cloakbrowser\n"
                "First import auto-downloads the stealth Chromium binary (~200MB, cached)."
            )

        proxy_url = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"

        # humanize=True turns on Bézier-curve mouse, per-character typing,
        # realistic scroll. Zero downside for our use case (Burp captures
        # the resulting HTTP traffic, not the input events) and it sidesteps
        # behavioral-fingerprint detectors that flag instant-coordinate
        # clicks even when the static fingerprint is clean.
        _browser = await launch_async(
            headless=True,
            proxy=proxy_url,
            humanize=True,
        )

        # ignore_https_errors is required for Burp's MITM CA. UA / timezone /
        # locale are baked into the CloakBrowser binary; overriding here would
        # conflict with the source-level patches.
        _context = await _browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
            java_script_enabled=True,
        )

        _page = await _context.new_page()
        return _browser, _context, _page


async def _shutdown_browser() -> bool:
    """Close the browser. Returns True if a browser was running."""
    global _browser, _context, _page
    was_running = _browser is not None
    if _browser:
        try:
            await _browser.close()
        except Exception:
            pass
    _browser = None
    _context = None
    _page = None
    return was_running
