"""Shared helpers for the Burp GUI capture tools (burp_ui package).

Filename/caption slugs, base64 PNG save, attach-twin selection, header/text
flattening for keyword scanning, and the OCR auto-redact pass. The @mcp.tool()
surfaces live in sibling modules: _capture (full window), _redact (censor an
existing shot), _message (one message auto-scrolled to a keyword).
"""

from __future__ import annotations

import asyncio
import base64
import re
from datetime import datetime
from pathlib import Path

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


def _hdr_line(h) -> str:
    """A proxy-history header entry ({name,value} dict or raw string) as text."""
    if isinstance(h, dict):
        return f"{h.get('name', '')}: {h.get('value', '')}"
    return str(h)


def _scan_text(detail: dict, which: str) -> str:
    """Flatten a proxy-history detail into text for keyword scanning — the request
    (line + headers + body) or the response (status + headers + body)."""
    if not isinstance(detail, dict):
        return ""
    parts: list[str] = []
    if which == "request":
        parts.append(f"{detail.get('method', '')} {detail.get('url', '')}")
        parts += [_hdr_line(h) for h in detail.get("request_headers", []) or []]
        parts.append(str(detail.get("request_body", "") or ""))
    else:
        parts.append(str(detail.get("status_code", "")))
        parts += [_hdr_line(h) for h in detail.get("response_headers", []) or []]
        parts.append(str(detail.get("response_body", "") or ""))
    return "\n".join(parts)


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
