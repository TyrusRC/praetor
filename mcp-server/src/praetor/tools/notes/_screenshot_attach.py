"""Attach a saved screenshot to a finding's evidence.

Screenshots from `burp_screenshot` / `browser_screenshot` land in
`.burp-intel/<domain>/screenshots/`. This links one to a finding so it renders
in `generate_report` (client-safe: filename only) and is copied into
`export_poc_bundle`. Additive evidence — allowed even on a LOCKED finding, since
it does not touch status / severity / impact (the frozen verdict, Rule 16b).

Stored on the finding as `evidence.screenshots = [{file, note}]`, where `file`
is the domain-relative `screenshots/<name>` — no `.burp-intel/` path, so the
report's internal-evidence filter never strips it.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._helpers import (
    _find_by_id,
    _findings_lock,
    _intel_dir,
    _load_findings_file,
    _safe_findings_path,
    _sanitized,
    _write_findings_file,
)

_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp")


def _rel_ref(name: str) -> str:
    return f"screenshots/{name}"


def _attach_screenshot(domain: str, finding_id: str, path: str, note: str = "",
                       step: str = "") -> dict:
    """Append `{file, note, step}` to the finding's `evidence.screenshots`.
    Idempotent by filename (a repeat updates note/step). `step` orders the shots
    as PoC steps in the report. Touches only findings.json, locked."""
    name = Path(path).name
    if not name.lower().endswith(_IMAGE_EXTS):
        return {"error": f"not an image file: {path!r}"}
    shot = _intel_dir() / _sanitized(domain) / "screenshots" / name
    if not shot.exists():
        return {"error": f"screenshot not found: {shot}"}

    fpath = _safe_findings_path(domain)
    ref = _rel_ref(name)
    with _findings_lock(fpath):
        store = _load_findings_file(fpath)
        findings = store.get("findings", [])
        idx, f = _find_by_id(findings, finding_id)
        if f is None:
            return {"error": f"finding {finding_id!r} not found for {domain!r}"}

        ev = f.get("evidence")
        if not isinstance(ev, dict):
            ev = {"note": str(ev)} if ev else {}
        shots = ev.get("screenshots")
        if not isinstance(shots, list):
            shots = []
        existing = next((s for s in shots
                         if isinstance(s, dict) and s.get("file") == ref), None)
        if existing is not None:
            if note:
                existing["note"] = note
            if step:
                existing["step"] = step
        else:
            entry = {"file": ref, "note": note}
            if step:
                entry["step"] = step
            shots.append(entry)
        ev["screenshots"] = shots
        f["evidence"] = ev
        findings[idx] = f
        store["findings"] = findings
        _write_findings_file(fpath, store)

    return {"ok": True, "finding_id": finding_id, "file": ref,
            "screenshots": len(shots), "note": note, "step": step}


def register(mcp: FastMCP):
    @mcp.tool()
    async def attach_screenshot(domain: str, finding_id: str, path: str,
                                note: str = "", step: str = "") -> dict:
        """Attach a saved screenshot to a finding — it then renders in the report + PoC bundle.

        Links a PNG already under .burp-intel/<domain>/screenshots/ (captured by
        burp_screenshot or browser_screenshot) to a finding's evidence. It appears
        in generate_report (client-safe — filename only, no internal path), ordered
        by `step`, and is copied into export_poc_bundle. Additive evidence: safe on
        a locked finding (does not change the frozen verdict).

        Args:
            domain: target domain.
            finding_id: saved-finding id.
            path: screenshot path or filename (the `saved` value from *_screenshot).
            note: short caption for the report.
            step: PoC step label (e.g. '1-baseline') — orders the shots in the report.
        """
        return _attach_screenshot(domain, finding_id, path, note, step)
