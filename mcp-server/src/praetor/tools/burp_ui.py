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


def _shot_name(tab: str, finding_id: str, step: str, note: str, ts: str) -> str:
    """Descriptive filename so the evidence + its PoC step are identifiable at a
    glance: `burp-<tab>-<finding_id>-step-<step>-<note-slug>-<ts>.png`. Empty
    parts are dropped."""
    parts = ["burp", _slug(tab) or "suite"]
    if finding_id.strip():
        parts.append(_slug(finding_id))
    if step.strip():
        parts.append("step-" + _slug(step))
    note_slug = _slug(note)
    if note_slug:
        parts.append(note_slug)
    parts.append(ts)
    return "-".join(p for p in parts if p) + ".png"


def _caption(step: str, note: str) -> str:
    """The on-image call-out banner text (PoC step + caption)."""
    step, note = step.strip(), note.strip()
    if step and note:
        return f"Step {step} — {note}"
    if step:
        return f"Step {step}"
    return note


def _save_shot(data: dict, domain: str, tab: str, note: str,
               finding_id: str = "", step: str = "") -> dict:
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
    path = out_dir / _shot_name(tab, finding_id, step, note, ts)
    path.write_bytes(raw)
    return {
        "saved": str(path),
        "width": data.get("width"),
        "height": data.get("height"),
        "title": data.get("title"),
        "tab": tab or "suite",
        "finding_id": finding_id,
        "step": step,
        "note": note,
    }


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def burp_screenshot(domain: str = "", tab: str = "", note: str = "",
                              finding_id: str = "", step: str = "",
                              scale: float = 2.0) -> dict:
        """Screenshot the Burp Suite window for evidence — optionally a named tab.

        Pass `tab` to bring that top-level Burp tab to front before capturing
        (Proxy, Repeater, Intruder, Organizer, Logger, Target, Dashboard, ...);
        matched case-insensitively by substring. Leave `tab` empty to capture
        whatever tab is currently selected. The return's `selected_tab` says which
        tab was actually shown (empty if the name didn't match — then it's the
        prior tab). Note: sub-tabs (e.g. Proxy > HTTP history vs Intercept) aren't
        individually selectable — `tab='Proxy'` shows Proxy with its last sub-tab;
        also, tool-sent traffic (curl/send_*) shows in Logger, browser traffic in
        Proxy > HTTP history.

        Saves a PNG under .burp-intel/<domain>/screenshots/ with a self-describing
        name — `burp-<tab>-<finding_id>-<note-slug>-<timestamp>.png` — so the
        evidence is identifiable at a glance. It feeds screenshot_gallery(domain)
        and per-finding evidence directly. Pass `finding_id` to attach it to that
        finding straight away (renders in the report + PoC bundle). Requires Burp
        running with its GUI (headless Burp returns a `headless` error).

        Capture is rendered at `scale`× (default 2×, capped to ~2K long side) so
        text is readable on FHD/2K without bloating the PNG. Pass `step` (e.g.
        '1-baseline', '2-attack', '3-result') to label the shot as a PoC step:
        it goes in the filename, is stamped as an on-image call-out banner, and
        orders the screenshots in the finding's report section.

        Args:
            domain: target the shot belongs to (its screenshots dir). Empty -> _burp.
            tab: top-level Burp tab to bring to front + label (proxy/repeater/...).
            note: short caption — banner text + finding caption + filename slug.
            finding_id: optional saved-finding id to attach the shot to.
            step: PoC step label (ordered in the report; shown on the banner).
            scale: render scale (default 2×; capped so the long side stays ~2K).
        """
        label = _caption(step, note)
        params = {"scale": str(scale)}
        if tab.strip():
            params["tab"] = tab
        if label:
            params["label"] = label
        data = await client.get("/api/ui/screenshot", params=params)
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, tab, note, finding_id, step)
        if "error" not in out:
            # Which tab the extension actually brought to front (empty if `tab`
            # didn't match a top-level Burp tab — the shot is the prior tab then).
            out["selected_tab"] = data.get("selected_tab", "")
            if finding_id and domain:
                from praetor.tools.notes._screenshot_attach import _attach_screenshot
                out["attached"] = _attach_screenshot(
                    domain, finding_id, out["saved"], note, step)
        return out
