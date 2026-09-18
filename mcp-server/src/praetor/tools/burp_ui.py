"""Burp Suite GUI capture — screenshot the Burp window for report evidence.

`browser_screenshot` captures the TARGET page; this captures the BURP window
(whatever tab the operator has on screen: Proxy > HTTP history, Repeater,
Intruder, Organizer, ...). Shots land in the same
`.burp-intel/<domain>/screenshots/` dir the browser tools use, so they drop
straight into `screenshot_gallery(domain)` and per-finding evidence.

`_save_shot` is pure-ish (decode + write); `burp_screenshot` adds the Burp call.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client


def _slug(text: str, maxlen: int = 40) -> str:
    """Filesystem-safe slug from free text (lowercase, dashes)."""
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return s[:maxlen].strip("-")


def _shot_name(tab: str, finding_id: str, note: str, ts: str) -> str:
    """Descriptive filename so the evidence is identifiable at a glance:
    `burp-<tab>-<finding_id>-<note-slug>-<ts>.png`. Empty parts are dropped."""
    parts = ["burp", _slug(tab) or "suite"]
    if finding_id.strip():
        parts.append(_slug(finding_id))
    note_slug = _slug(note)
    if note_slug:
        parts.append(note_slug)
    parts.append(ts)
    return "-".join(p for p in parts if p) + ".png"


def _save_shot(data: dict, domain: str, tab: str, note: str,
               finding_id: str = "") -> dict:
    """Decode the base64 PNG from the extension and save it under the domain's
    screenshots dir with a self-describing name. Returns the envelope or error."""
    b64 = data.get("png_base64") if isinstance(data, dict) else None
    if not b64:
        return {"error": "no image returned from Burp", "raw": data}
    try:
        raw = base64.b64decode(b64)
    except Exception as exc:  # malformed transport
        return {"error": f"bad base64 image: {exc}"}

    host = (domain or "").strip() or "_burp"
    out_dir = Path.cwd() / ".burp-intel" / host / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = out_dir / _shot_name(tab, finding_id, note, ts)
    path.write_bytes(raw)
    return {
        "saved": str(path),
        "width": data.get("width"),
        "height": data.get("height"),
        "title": data.get("title"),
        "tab": tab or "suite",
        "finding_id": finding_id,
        "note": note,
    }


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def burp_screenshot(domain: str = "", tab: str = "", note: str = "",
                              finding_id: str = "") -> dict:
        """Screenshot the Burp Suite window (whatever tab is on screen) for evidence.

        Captures the FULL Burp window as it currently looks — SELECT the tab you
        want first in Burp (Proxy > HTTP history, Repeater, Intruder, Organizer,
        Logger, ...), then call this. Montoya exposes the window, not individual
        tool tabs, so `tab` is a label recorded in the filename/return, not a
        selector — the on-screen selection is what gets captured.

        Saves a PNG under .burp-intel/<domain>/screenshots/ with a self-describing
        name — `burp-<tab>-<finding_id>-<note-slug>-<timestamp>.png` — so the
        evidence is identifiable at a glance. It feeds screenshot_gallery(domain)
        and per-finding evidence directly. Pass `finding_id` to attach it to that
        finding straight away (renders in the report + PoC bundle). Requires Burp
        running with its GUI (headless Burp returns a `headless` error).

        Args:
            domain: target the shot belongs to (its screenshots dir). Empty -> _burp.
            tab: label for what's on screen (history/repeater/intruder/organizer).
            note: short caption stored in the return / used as the finding caption.
            finding_id: optional saved-finding id to attach the shot to.
        """
        data = await client.get("/api/ui/screenshot")
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, tab, note, finding_id)
        if "error" not in out and finding_id and domain:
            from praetor.tools.notes._screenshot_attach import _attach_screenshot
            out["attached"] = _attach_screenshot(domain, finding_id, out["saved"], note)
        return out
