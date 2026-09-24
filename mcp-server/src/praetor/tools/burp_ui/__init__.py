"""Burp Suite GUI capture — screenshot the Burp window for report evidence.

`browser_screenshot` captures the TARGET page; these tools capture the BURP
window. Shots land in `.burp-intel/<domain>/screenshots/` (shared with the
browser tools), so they drop into `screenshot_gallery(domain)` and per-finding
evidence. Split by concern:

- _capture  — burp_screenshot (full window, any tab/row/button)
- _redact   — auto_redact_screenshot / redact_screenshot (censor secrets)
- _message  — screenshot_message (one message auto-scrolled to a keyword)
- _shared   — save / caption / attach / OCR-redact helpers

`client` and the `_save_shot` / `_pick_attach` / `_caption` helpers are
re-exported here so existing importers (server.py, tests) are unchanged.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor import client

from . import _capture, _message, _redact
from ._shared import _caption, _pick_attach, _save_shot

__all__ = ["register", "client", "_save_shot", "_pick_attach", "_caption"]


def register(mcp: FastMCP) -> None:
    _capture.register(mcp)
    _redact.register(mcp)
    _message.register(mcp)
