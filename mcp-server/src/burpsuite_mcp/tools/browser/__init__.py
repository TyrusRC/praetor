"""browser/ — stealth headless browser routed through Burp proxy.

Split from a single 522-line browser.py:

    _lifecycle.py — CloakBrowser launch / reuse / close + lock
    nav.py        — browser_navigate, browser_crawl, browser_close
    interact.py   — browser_click, browser_fill, browser_submit_form,
                    browser_interact_all
    inspect.py    — browser_get_page_info, browser_execute_js, browser_screenshot

`from burpsuite_mcp.tools import browser; browser.register(mcp)` keeps working.
"""

from mcp.server.fastmcp import FastMCP

from . import inspect, interact, nav
from ._lifecycle import _ensure_browser, _get_lock, _shutdown_browser

__all__ = ["register", "_ensure_browser", "_get_lock", "_shutdown_browser"]


def register(mcp: FastMCP):
    nav.register(mcp)
    interact.register(mcp)
    inspect.register(mcp)
