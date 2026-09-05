"""import_scan_results — normalize external scanner output into findings.

Turns Praetor into a consolidation hub (PlexTrac/Dradis-style): parse a
scanner export, normalize to Praetor finding dicts, and merge into
findings.json with the SAME dedup key the native pipeline uses
(_dedupe_finding: endpoint+vuln_type+title+parameter).

Imported findings enter as status='suspected' with a `source` tag — they are
leads from a scanner, not Praetor-verified, so the true-positives-only report
rule (Rule 16) still holds until they pass verify/assess.

XML formats are parsed with defusedxml (XXE / billion-laughs safe) because
scanner output is untrusted input. `parse_*` / `merge_imported` are pure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import fromstring as _xml_fromstring
from mcp.server.fastmcp import FastMCP

from .._vuln_class import canonical
from ..notes._helpers import _dedupe_finding

_REAL_SEV = {"critical", "high", "medium", "low"}
# Nessus/OpenVAS numeric severity -> Praetor tier. 0/info is dropped.
_NESSUS_SEV = {"4": "critical", "3": "high", "2": "medium", "1": "low"}


def _slug_to_vuln_type(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(title).lower()).strip("_")
    return canonical(slug) or slug


def _finding(title, severity, endpoint, source, *, parameter="", evidence="") -> dict:
    return {
        "title": str(title).strip(),
        "severity": severity,
        "endpoint": str(endpoint).strip(),
        "parameter": parameter,
        "vuln_type": _slug_to_vuln_type(title),
        "status": "suspected",
        "source": source,
        "evidence": {"raw": str(evidence)[:2000]} if evidence else {},
    }


def parse_nuclei(text: str) -> list[dict]:
    """Nuclei JSONL export -> finding dicts. Drops info/unknown severity."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info", {}) or {}
        sev = str(info.get("severity", "")).lower()
        if sev not in _REAL_SEV:
            continue
        endpoint = row.get("matched-at") or row.get("host") or ""
        out.append(
            _finding(
                info.get("name") or row.get("template-id", "finding"),
                sev,
                endpoint,
                "nuclei",
                evidence=row.get("extracted-results") or row.get("template-id", ""),
            )
        )
    return out


def parse_nessus(xml: str) -> list[dict]:
    """Nessus .nessus (v2) export -> finding dicts. Drops severity 0 (info).

    Raises defusedxml.common.EntitiesForbidden on any entity declaration.
    """
    root = _xml_fromstring(xml)
    out: list[dict] = []
    for host in root.iter("ReportHost"):
        hostname = host.get("name", "")
        for item in host.iter("ReportItem"):
            sev = _NESSUS_SEV.get(item.get("severity", "0"))
            if sev is None:
                continue
            port = item.get("port", "")
            endpoint = f"{hostname}:{port}" if port and port != "0" else hostname
            po = item.find("plugin_output")
            out.append(
                _finding(
                    item.get("pluginName", "finding"),
                    sev,
                    endpoint,
                    "nessus",
                    evidence=(po.text if po is not None else "") or "",
                )
            )
    return out


_PARSERS = {"nuclei": parse_nuclei, "nessus": parse_nessus}


def _detect_format(path: str, text: str) -> str:
    low = path.lower()
    if low.endswith(".nessus"):
        return "nessus"
    if low.endswith(".jsonl") or low.endswith(".json"):
        return "nuclei"
    head = text.lstrip()[:200]
    if "NessusClientData" in head:
        return "nessus"
    if head.startswith("{"):
        return "nuclei"
    return ""


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


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def import_scan_results(
        source: str, domain: str, fmt: str = "auto"
    ) -> dict:
        """Import a scanner export into a domain's findings (dedup-merged).

        Supported fmt: nuclei (JSONL), nessus (.nessus XML), or 'auto'.
        Imported findings enter as status='suspected' with a `source` tag —
        verify before reporting. Returns {parsed, created, updated, by_severity}.
        """
        p = Path(source)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return {"error": f"cannot read '{source}': {e}"}

        chosen = fmt if fmt != "auto" else _detect_format(source, text)
        parser = _PARSERS.get(chosen)
        if parser is None:
            return {"error": f"unsupported format '{chosen or fmt}'", "valid": sorted(_PARSERS)}

        try:
            rows = parser(text)
        except Exception as e:  # defusedxml raises on XXE; surface, don't crash
            return {"error": f"parse failed ({type(e).__name__}): {e}"}

        fpath = Path(".burp-intel") / domain / "findings.json"
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {"findings": []}
        existing = data.get("findings", [])

        merged, created, updated = merge_imported(existing, rows)
        # assign ids to newly created imports lacking one
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
        return {
            "source_format": chosen,
            "parsed": len(rows),
            "created": created,
            "updated": updated,
            "by_severity": by_sev,
        }
