"""Burp Suite GUI capture — screenshot the Burp window for report evidence.

`browser_screenshot` captures the TARGET page; this captures the BURP window
(whatever tab the operator has on screen: Proxy > HTTP history, Repeater,
Intruder, Organizer, ...). Shots land in the same
`.burp-intel/<domain>/screenshots/` dir the browser tools use, so they drop
straight into `screenshot_gallery(domain)` and per-finding evidence.

`_save_shot` is pure-ish (decode + write); `burp_screenshot` adds the Burp call.
"""

from __future__ import annotations

import asyncio
import base64
import re
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.notes._findings_io import _sanitized


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

    # Sanitize the domain the SAME way every downstream consumer does
    # (_attach_screenshot / _safe_findings_path / poc_bundle all use _sanitized),
    # so the save dir agrees with them and path traversal is closed.
    if (domain or "").strip():
        try:
            host = _sanitized(domain)
        except ValueError as exc:
            return {"error": f"invalid domain {domain!r}: {exc}"}
    else:
        host = "_burp"
    out_dir = Path.cwd() / ".burp-intel" / host / "screenshots"
    # Microseconds so two captures in the same second don't overwrite silently.
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = out_dir / _shot_name(tab, finding_id, step, note, ts)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    except OSError as exc:
        return {"error": f"failed to save screenshot: {exc}"}
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


def _pick_attach(saved: str, redacted: str, mode: str) -> str:
    """Which screenshot to attach to a finding (⇒ ships in report + PoC bundle).

    'auto' (default) prefers the REDACTED twin when one exists so a secret never
    reaches the deliverable, else the naked shot; 'naked' forces the raw shot;
    'none' attaches nothing (returns ""). Unknown modes fall back to 'auto'.
    """
    m = (mode or "auto").strip().lower()
    if m == "none":
        return ""
    if m == "naked":
        return saved
    return redacted or saved   # auto: redacted wins when present


async def _run_auto_redact(path: str, out_path: str = "",
                           style: str = "pixel", coverage: float = 0.5) -> dict:
    """OCR-detect secrets in `path` and write a redacted twin. Naked stays put.

    Default: pixel-mosaic the trailing half of each value (label/prefix stays
    readable). `style="solid"` for an opaque fill; `coverage=1.0` covers all.
    """
    from praetor.tools._redact_ocr import detect_sensitive_boxes, tesseract_available
    p = Path(path)
    if not p.exists():
        return {"error": f"screenshot not found: {path}"}
    if not tesseract_available():
        return {"error": "tesseract not installed",
                "hint": "install the free tesseract-ocr (apt/brew) — see setup.sh"}
    boxes = await asyncio.to_thread(detect_sensitive_boxes, str(p), coverage)
    if not boxes:
        return {"redacted": "", "regions": 0, "note": "no sensitive spans detected by OCR"}
    b64 = base64.b64encode(p.read_bytes()).decode()
    data = await client.post("/api/ui/redact",
                             json={"png_base64": b64, "boxes": boxes, "style": style})
    if isinstance(data, dict) and "error" in data:
        return data
    rb64 = data.get("png_base64") if isinstance(data, dict) else None
    if not rb64:
        return {"error": "no image returned from redact", "raw": data}
    out = Path(out_path.strip()) if out_path.strip() else p.with_name(p.stem + "-redacted.png")
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(base64.b64decode(rb64))
    except (OSError, ValueError) as exc:
        return {"error": f"failed to save redacted image: {exc}"}
    return {"redacted": str(out), "regions": len(boxes), "style": style}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def burp_screenshot(domain: str = "", tab: str = "", subtab: str = "",
                              note: str = "", finding_id: str = "", step: str = "",
                              scale: float = 2.0, banner: bool = False,
                              trademark: str = "", click_button: str = "",
                              select_row: str = "", restore: bool = True,
                              auto_redact: bool = False, attach: str = "auto") -> dict:
        """Screenshot the Burp Suite window for evidence — optionally a named tab.

        Pass `tab` to bring that top-level Burp tab to front before capturing
        (Proxy, Repeater, Intruder, Organizer, Logger, Target, Dashboard, ...) and
        `subtab` to select a nested sub-tab within it (e.g. tab='proxy',
        subtab='http history'); both match case-insensitively (exact > prefix >
        substring). Leave them empty to capture whatever is currently selected.
        The return's `selected_tab` / `selected_subtab` say what was actually
        shown (empty if the name didn't match — then it's the prior selection).
        Note: tool-sent traffic (curl/send_*) shows in Logger, browser traffic in
        Proxy > HTTP history.

        `click_button='<label>'` clicks a real Burp button (matched by text /
        tooltip / accessible-name) in the selected tab BEFORE capturing, so the
        action runs THROUGH the UI and its result renders. Works for STANDARD Swing
        buttons: Collaborator ('Poll now', 'Copy to clipboard', 'HTTP'/'DNS'/'SMTP'),
        Settings, Help, Add, etc. `clicked_button` echoes the label if found+enabled+
        clicked (waits ~2.5s to render); `available_buttons` lists what's clickable
        in that tab (a disabled button won't click — e.g. 'Poll now' before a payload
        exists). EXCEPTION: Repeater's 'Send' is a custom-painted control, NOT a
        Swing button — it CANNOT be clicked from code. Fire Repeater with
        repeater_resend / curl_request (they return the parsed response, which is
        the evidence, Rule 13a) and screenshot the request for context.
        Pair with tab=/subtab= to select the surface first.

        `select_row='<#>'` (a Burp "#" entry number) or `select_row='last'` selects
        that row in the selected tab's main TABLE (Proxy HTTP history, Logger, ...)
        and scrolls it into view, so the row's request/response detail renders and
        the shot shows a SPECIFIC request — e.g.
        burp_screenshot(tab='proxy', subtab='http history', select_row='last').
        `selected_row` in the return is the chosen 0-based view row (-1 if none).

        Saves a PNG under .burp-intel/<domain>/screenshots/ with a self-describing
        name — `burp-<tab>-<finding_id>-<note-slug>-<timestamp>.png` — so the
        evidence is identifiable at a glance. It feeds screenshot_gallery(domain)
        and per-finding evidence directly. Pass `finding_id` to attach it to that
        finding straight away (renders in the report + PoC bundle). Requires Burp
        running with its GUI (headless Burp returns a `headless` error).

        NON-DISRUPTIVE by default (`restore=True`): the operator's current view —
        selected tab, sub-tab, table row, split layout — is snapshotted before the
        capture navigates and restored right after, so this never leaves a human's
        Burp on a different tab/selection than they had it (the capture is also
        occlusion-immune and doesn't steal window focus). A button CLICK is a real
        action and is not undone. `restore=False` leaves the navigated view.

        Capture is rendered at `scale`× (default 2×, capped to ~2K long side) so
        text is readable on FHD/2K without bloating the PNG. `step` (e.g.
        '1-baseline', '2-attack', '3-result') goes in the filename and orders the
        shots in the finding's report — it does NOT draw on the image.

        `banner` is OPT-IN and defaults OFF — ASK the operator before enabling it.
        When on, a footer strip is appended BELOW the screenshot (nothing on the
        image is covered) with the step/caption on the left and `trademark` (if
        given) on the right.

        `auto_redact=True` OCR-scans the saved shot and writes a redacted twin
        (`out['redacted']`) with secrets (cookies / tokens / keys / JWTs / emails)
        pixel-mosaicked — the naked shot stays at `out['saved']`, so the operator
        keeps both. Needs tesseract (see setup.sh); for precise control use
        `redact_screenshot(path, boxes)` / `auto_redact_screenshot(path)`.

        `attach` picks which twin is linked to `finding_id` (⇒ what ships in the
        report + PoC bundle): 'auto' (default) ships the REDACTED twin when one
        exists — so a secret never reaches the deliverable — else the naked shot;
        'naked' forces the raw shot; 'none' captures without attaching.
        `attached_file` echoes the filename that was linked.

        SENSITIVE: this captures the WHOLE Burp window, which may show unrelated
        secrets (other tabs, tokens, other in-scope hosts, cross-customer proxy
        rows). Prefer a specific `tab`, and review/redact before shipping it in a
        client deliverable (export_poc_bundle copies the PNG out verbatim).

        Args:
            domain: target the shot belongs to (its screenshots dir). Empty -> _burp.
            tab: top-level Burp tab to bring to front + label (proxy/repeater/...).
            note: short caption — finding caption + filename slug (+ footer if banner).
            finding_id: optional saved-finding id to attach the shot to.
            step: PoC step label (ordered in the report; footer text if banner on).
            scale: render scale (default 2×; capped so the long side stays ~2K).
            banner: append a footer caption strip below the shot (ask first; default off).
            trademark: optional brand text, right side of the footer (implies banner).
            auto_redact: OCR-detect secrets and write a pixel-mosaicked redacted twin.
            attach: which twin to link to finding_id — 'auto' (redacted if present,
                else naked), 'naked', or 'none'. Default 'auto' keeps secrets out of
                the deliverable.
        """
        label = _caption(step, note) if (banner or trademark.strip()) else ""
        params = {"scale": str(scale)}
        if tab.strip():
            params["tab"] = tab
        if subtab.strip():
            params["subtab"] = subtab
        if click_button.strip():
            params["click_button"] = click_button.strip()
        if select_row.strip():
            params["select_row"] = select_row.strip()
        if not restore:
            params["restore"] = "false"
        if label:
            params["label"] = label
        if trademark.strip():
            params["trademark"] = trademark
        data = await client.get("/api/ui/screenshot", params=params)
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, tab, note, finding_id, step)
        if "error" not in out:
            # Which tab (and nested sub-tab) the extension actually brought to
            # front — empty if the name didn't match (the shot is the prior tab).
            out["selected_tab"] = data.get("selected_tab", "")
            out["selected_subtab"] = data.get("selected_subtab", "")
            out["clicked_button"] = data.get("clicked_button", "")
            out["selected_row"] = data.get("selected_row", -1)
            # Auto-redact: OCR-detect secrets and save a redacted twin. The naked
            # shot (out['saved']) stays; the operator picks which goes in the report.
            if auto_redact:
                r = await _run_auto_redact(out["saved"])
                out["redacted"] = r.get("redacted", "")
                out["redacted_regions"] = r.get("regions", 0)
                if "error" in r:
                    out["redact_error"] = r["error"]
            # Which twin gets attached to the finding (⇒ ships in report + PoC
            # bundle). 'auto' ships the REDACTED twin when one exists so a secret
            # never reaches the deliverable; 'naked' forces the raw shot; 'none'
            # skips attach.
            attach_path = _pick_attach(out["saved"], out.get("redacted", ""), attach)
            if finding_id and domain and attach_path:
                from praetor.tools.notes._screenshot_attach import _attach_screenshot
                # off-thread: the attach takes a blocking flock on findings.json.
                out["attached"] = await asyncio.to_thread(
                    _attach_screenshot, domain, finding_id, attach_path, note, step)
                out["attached_file"] = Path(attach_path).name
        return out

    @mcp.tool()
    async def auto_redact_screenshot(path: str, out_path: str = "",
                                     style: str = "pixel", coverage: float = 0.5) -> dict:
        """Auto-detect + redact secrets in a screenshot via OCR — keeps a naked + redacted pair.

        Runs the free `tesseract` OCR over the saved PNG, flags sensitive spans
        (cookies, session tokens, API keys, JWTs, emails — by value shape or a
        sensitive header key on the line), and censors them via /api/ui/redact.
        Default: a coarse pixel-mosaic over the trailing HALF of each value, so
        the label/prefix stays readable (which header, which token) and only the
        high-entropy tail is hidden. The original (naked) is left untouched; a
        `<name>-redacted.png` twin is written. The operator chooses which to put in
        the report. No model step, no re-capture. Needs tesseract (apt/brew; setup.sh).

        Args:
            path: the screenshot to scan (a burp_screenshot `saved` path).
            out_path: where to write the redacted twin (default `<name>-redacted.png`).
            style: "pixel" (coarse mosaic, default) or "solid" (opaque fill).
            coverage: fraction of each value covered from the right (0.5 = back half,
                1.0 = whole value). Solid + coverage=1.0 is the fully-irreversible option.
        """
        r = await _run_auto_redact(path, out_path, style=style, coverage=coverage)
        r.setdefault("naked", path)
        return r

    @mcp.tool()
    async def redact_screenshot(path: str, boxes: list, out_path: str = "",
                                style: str = "pixel") -> dict:
        """Redact sensitive regions in an EXISTING screenshot — censor boxes ON TOP.

        Does NOT re-capture or re-render; it censors the saved PNG to hide cookies,
        session tokens, API keys, PII, etc. before the shot goes in a report.
        `style="pixel"` (default) draws a coarse, non-invertible mosaic; "solid" an
        opaque fill.

        Workflow: read the screenshot first (so you SEE it and its coordinate
        mapping), find the sensitive spans, then pass their boxes. Size each box to
        cover only the sensitive part — redact half a value and leave a prefix
        (e.g. cover the tail of `PHPSESSID=abcd…`), so the finding stays legible.

        Args:
            path: the screenshot to redact (e.g. a burp_screenshot `saved` path).
            boxes: list of [x, y, w, h] in the image's OWN pixel coordinates (the
                saved PNG is 2×, ~2560px wide — use the coordinates you read off it,
                not the displayed/downscaled ones).
            out_path: where to save; default `<name>-redacted.png` beside the source.
            style: "pixel" (coarse mosaic, default) or "solid" (opaque fill).
        """
        p = Path(path)
        if not p.exists():
            return {"error": f"screenshot not found: {path}"}
        try:
            b64 = base64.b64encode(p.read_bytes()).decode()
        except OSError as exc:
            return {"error": f"read failed: {exc}"}
        norm = []
        for b in boxes or []:
            if isinstance(b, (list, tuple)) and len(b) >= 4:
                try:
                    norm.append([int(b[0]), int(b[1]), int(b[2]), int(b[3])])
                except (TypeError, ValueError):
                    continue
        if not norm:
            return {"error": "no valid boxes — each must be [x, y, w, h]"}
        data = await client.post("/api/ui/redact",
                                 json={"png_base64": b64, "boxes": norm, "style": style})
        if isinstance(data, dict) and "error" in data:
            return data
        rb64 = data.get("png_base64") if isinstance(data, dict) else None
        if not rb64:
            return {"error": "no image returned from redact", "raw": data}
        out = Path(out_path.strip()) if out_path.strip() else p.with_name(p.stem + "-redacted.png")
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(base64.b64decode(rb64))
        except (OSError, ValueError) as exc:
            return {"error": f"failed to save redacted image: {exc}"}
        return {"saved": str(out), "source": str(p), "style": style,
                "boxes_applied": data.get("boxes_applied", len(norm))}
