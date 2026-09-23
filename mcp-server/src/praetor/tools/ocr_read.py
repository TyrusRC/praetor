"""read_screenshot_text — OCR a saved screenshot into TEXT, not vision tokens.

Praetor's screenshot tools (`burp_screenshot`, `browser_screenshot`) already save
PNGs to `.burp-intel/<domain>/screenshots/` and return small dicts (no image
bytes to the model). The remaining cost is the agent host-`Read`-ing that PNG
back as an IMAGE to find leads (forms, endpoints, error strings) — ~1.5k+ vision
tokens per tile. Most of what recon needs from a screenshot is the TEXT on it,
which OCR extracts for a few hundred plain-text tokens instead.

Runs the free `tesseract` CLI (same shell-out pattern as `_redact_ocr.py` — no
pytesseract/Pillow dependency) and returns the extracted text. Degrades
gracefully with a clear message when tesseract isn't installed (optional dep,
see setup.sh); the caller's fallback is then a visual `Read` of the PNG, or the
`screenshot-triage` haiku agent.

`_resolve_screenshot_path` and `_tesseract_available` are pure; `_run_tesseract_text`
shells out.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.notes._findings_io import _sanitized


def _tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


def _run_tesseract_text(path: str) -> str:
    """Plain-text OCR via the tesseract CLI. Empty string on failure (never raises)."""
    try:
        proc = subprocess.run(
            ["tesseract", str(path), "stdout", "--psm", "11"],
            capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip()


def _resolve_screenshot_path(path: str, domain: str, filename: str) -> Path | None:
    """An explicit `path` (absolute or relative) wins; otherwise `domain` +
    `filename` resolve under `.burp-intel/<domain>/screenshots/`. `filename` is
    reduced to its basename so it can't escape that directory. Returns None when
    neither form of input was given."""
    if path.strip():
        return Path(path.strip())
    if domain.strip() and filename.strip():
        safe_name = Path(filename.strip()).name
        return Path.cwd() / ".burp-intel" / _sanitized(domain) / "screenshots" / safe_name
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def read_screenshot_text(path: str = "", domain: str = "", filename: str = "") -> dict:
        """OCR a saved screenshot and return its TEXT — cheap recon, not vision tokens.

        Use this instead of host-`Read`-ing a screenshot PNG during recon/discovery:
        the OCR'd text (form labels, visible URLs, error strings, auth/role markers)
        covers most leads for a few hundred text tokens versus ~1.5k+ vision tokens
        per image tile. Fall back to a visual read only when the OCR text is empty
        or the lead genuinely needs the image (layout, a graphic, a QR code).

        Args:
            path: absolute or relative path to the PNG. Takes priority over
                domain/filename when given.
            domain: target domain — used with `filename` to resolve a shot under
                `.burp-intel/<domain>/screenshots/<filename>` (where `burp_screenshot`
                / `browser_screenshot` save).
            filename: the screenshot's basename under that domain's screenshots dir.

        Returns:
            `{"path": ..., "text": ..., "chars": N}` on success, or `{"error": ...}`
            — including a graceful message (with a `hint`) when tesseract isn't
            installed, so the caller can fall back to a visual read.
        """
        try:
            resolved = _resolve_screenshot_path(path, domain, filename)
        except ValueError as exc:
            return {"error": str(exc)}
        if resolved is None:
            return {"error": "provide either `path`, or both `domain` and `filename`"}
        if not resolved.exists():
            return {"error": f"screenshot not found: {resolved}"}
        if not _tesseract_available():
            return {
                "error": "tesseract not installed",
                "hint": "install the free tesseract-ocr (apt/brew — see setup.sh); "
                        "until then, fall back to a visual read of the PNG or the "
                        "screenshot-triage agent",
            }
        text = await asyncio.to_thread(_run_tesseract_text, str(resolved))
        return {"path": str(resolved), "text": text, "chars": len(text)}
