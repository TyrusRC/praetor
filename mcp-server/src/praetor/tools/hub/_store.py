"""Finding store: merge normalized rows into a domain's findings.json.

merge_imported dedups by the native key (endpoint+vuln_type+title+parameter);
_apply_rows writes the store and assigns ids; _burp_rows normalizes Burp Pro's
live scanner findings into the same shape so both engines merge into one stream.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..notes._helpers import _dedupe_finding
from ._parsers import _REAL_SEV, _finding


def merge_imported(
    existing: list[dict], rows: list[dict]
) -> tuple[list[dict], int, int]:
    """Merge normalized rows into existing findings via the native dedup key."""
    created = updated = 0
    for row in rows:
        existing, action, _ = _dedupe_finding(existing, row)
        if action == "created":
            created += 1
        else:
            updated += 1
    return existing, created, updated


def _apply_rows(domain: str, rows: list[dict]) -> dict:
    """Dedup-merge rows into a domain's findings.json, assign ids, write back.

    Returns {parsed, created, updated, by_severity}. The single place both
    import_scan_results and merge_scan converge on.
    """
    fpath = Path(".burp-intel") / domain / "findings.json"
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {"findings": []}
    existing = data.get("findings", [])

    merged, created, updated = merge_imported(existing, rows)
    max_num = 0
    for f in merged:
        m = re.match(r"f(\d+)", str(f.get("id", "")))
        if m:
            max_num = max(max_num, int(m.group(1)))
    for f in merged:
        if not f.get("id"):
            max_num += 1
            f["id"] = f"f{max_num:03d}"

    data["findings"] = merged
    fpath.parent.mkdir(parents=True, exist_ok=True)
    fpath.write_text(json.dumps(data, indent=2), encoding="utf-8")

    by_sev: dict[str, int] = {}
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    return {"parsed": len(rows), "created": created, "updated": updated, "by_severity": by_sev}


def _burp_rows(items: list[dict]) -> list[dict]:
    """Normalize Burp Pro live scanner findings (/api/scanner/findings items)
    into finding dicts. Drops INFORMATION severity."""
    out: list[dict] = []
    for it in items:
        sev = str(it.get("severity", "")).lower()
        if sev not in _REAL_SEV:
            continue
        out.append(
            _finding(
                it.get("name") or "finding",
                sev,
                it.get("base_url") or it.get("url") or "",
                "burp",
                evidence=it.get("detail") or "",
            )
        )
    return out
