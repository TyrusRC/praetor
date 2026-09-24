"""auto_redact_screenshot / redact_screenshot — censor secrets in a shot."""

from __future__ import annotations

import base64
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._shared import _run_auto_redact


def register(mcp: FastMCP) -> None:
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
        NEVER box a whole request or response: a screenshot is PoC the reader must
        READ, so redact only the sensitive spans and keep everything else readable.

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

