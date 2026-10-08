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


_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low"}


def _sarif_sev(result: dict, rule: dict) -> str:
    """SARIF severity: prefer a CVSS security-severity, else the level."""
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    ss = props.get("security-severity")
    if ss is not None:
        try:
            v = float(ss)
            return ("critical" if v >= 9 else "high" if v >= 7
                    else "medium" if v >= 4 else "low")
        except (TypeError, ValueError):
            pass
    return _SARIF_LEVEL.get(str(result.get("level", "")).lower(), "")


def parse_sarif(text: str) -> list[dict]:
    """SARIF 2.1.0 (SAST/DAST/IaC/SCA) -> finding dicts. Drops info/none level."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out: list[dict] = []
    for run in doc.get("runs", []) or []:
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name")) or "sarif"
        rules = {r.get("id"): r for r in
                 (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])}
        for res in run.get("results", []) or []:
            rule = rules.get(res.get("ruleId"), {})
            sev = _sarif_sev(res, rule)
            if sev not in _REAL_SEV:
                continue
            title = (res.get("ruleId") or (rule.get("name")) or "sarif finding")
            loc = ""
            try:
                pl = res["locations"][0]["physicalLocation"]
                uri = pl["artifactLocation"]["uri"]
                line = (pl.get("region") or {}).get("startLine")
                loc = f"{uri}:{line}" if line else uri
            except (KeyError, IndexError, TypeError):
                pass
            msg = (res.get("message") or {}).get("text", "")
            out.append(_finding(title, sev, loc, f"sarif:{tool}", evidence=msg))
    return out


def parse_burp_xml(xml: str) -> list[dict]:
    """Burp Suite issue export (<issues><issue>...) -> finding dicts.

    Maps severity High/Medium/Low; drops 'Information'. endpoint = host+path.
    Raises defusedxml.common.EntitiesForbidden on any entity declaration.
    """
    root = _xml_fromstring(xml)
    out: list[dict] = []
    for issue in root.iter("issue"):
        sev = (issue.findtext("severity") or "").strip().lower()
        if sev not in _REAL_SEV:  # drops 'information'
            continue
        host = (issue.findtext("host") or "").strip()
        path = (issue.findtext("path") or issue.findtext("location") or "").strip()
        endpoint = f"{host}{path}" if path else host
        out.append(
            _finding(
                issue.findtext("name") or "burp issue",
                sev,
                endpoint,
                "burp",
                evidence=issue.findtext("issueDetail") or issue.findtext("issueBackground") or "",
            )
        )
    return out


def _cvss_band(score: Any) -> str:
    """CVSS base score -> Praetor tier. >0 but sub-4 is low; 0/invalid drops."""
    try:
        v = float(score)
    except (TypeError, ValueError):
        return ""
    if v >= 9:
        return "critical"
    if v >= 7:
        return "high"
    if v >= 4:
        return "medium"
    if v > 0:
        return "low"
    return ""


def parse_openvas(xml: str) -> list[dict]:
    """Greenbone/OpenVAS GVM report (<report>...<results><result>) -> findings.

    severity is a CVSS float in <severity>, falling back to <threat>
    High/Medium/Low. Log/0.0 results are dropped. endpoint = host(+port).
    Raises defusedxml.common.EntitiesForbidden on any entity declaration.
    """
    root = _xml_fromstring(xml)
    out: list[dict] = []
    for res in root.iter("result"):
        sev = _cvss_band(res.findtext("severity"))
        if not sev:
            threat = (res.findtext("threat") or "").strip().lower()
            sev = threat if threat in _REAL_SEV else ""
        if sev not in _REAL_SEV:
            continue
        host = (res.findtext("host") or "").strip()
        port = (res.findtext("port") or "").strip()
        endpoint = f"{host}:{port}" if port and port.lower() != "general/tcp" else host
        nvt = res.find("nvt")
        title = (res.findtext("name")
                 or (nvt.findtext("name") if nvt is not None else "")
                 or "openvas finding")
        out.append(
            _finding(title, sev, endpoint, "openvas",
                     evidence=res.findtext("description") or "")
        )
    return out


_ZAP_RISK = {"3": "high", "2": "medium", "1": "low"}


def parse_zap(text: str) -> list[dict]:
    """OWASP ZAP JSON report -> finding dicts. riskcode 3/2/1 -> high/med/low;
    0 (informational) is dropped. One finding per alert."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out: list[dict] = []
    for site in doc.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            sev = _ZAP_RISK.get(str(alert.get("riskcode", "")).strip())
            if sev is None:
                continue
            instances = alert.get("instances") or []
            first = instances[0] if instances else {}
            endpoint = first.get("uri", "") or site.get("@name", "") or ""
            out.append(
                _finding(
                    alert.get("alert") or alert.get("name") or "zap alert",
                    sev,
                    endpoint,
                    "zap",
                    parameter=first.get("param", "") or "",
                    evidence=alert.get("desc") or alert.get("otherinfo") or "",
                )
            )
    return out


def parse_assay(text: str) -> list[dict]:
    """assay --json export -> finding dicts. Drops info/unknown severity.

    assay emits one JSON object: {tool, scan_result: {findings: [...]}, ...}.
    Each finding's `type` is the canonical class (SQL Injection, IDOR, ...),
    so it drives vuln_type for dedup; the description goes to evidence.
    """
    out: list[dict] = []
    try:
        doc = json.loads(text)
    except ValueError:
        return out
    scan_result = doc.get("scan_result") or {}
    for row in scan_result.get("findings") or []:
        sev = str(row.get("severity", "")).lower()
        if sev not in _REAL_SEV:
            continue
        endpoint = row.get("url") or ""
        klass = row.get("type") or row.get("title") or "finding"
        out.append(
            _finding(
                klass,
                sev,
                endpoint,
                "assay",
                parameter=row.get("parameter") or "",
                evidence=row.get("description") or row.get("evidence") or row.get("request") or "",
            )
        )
    return out


_PARSERS = {
    "nuclei": parse_nuclei,
    "assay": parse_assay,
    "nessus": parse_nessus,
    "sarif": parse_sarif,
    "burp": parse_burp_xml,
    "openvas": parse_openvas,
    "zap": parse_zap,
}


def _detect_format(path: str, text: str) -> str:
    low = path.lower()
    if low.endswith(".nessus"):
        return "nessus"
    head = text.lstrip()
    sniff = head[:400]
    if sniff.startswith("<"):
        if "NessusClientData" in sniff:
            return "nessus"
        if "<issues" in sniff or "burp" in sniff.lower():
            return "burp"
        if "<report" in sniff:  # GVM/OpenVAS report (vendor marker optional)
            return "openvas"
        return ""
    if sniff.startswith("{"):
        # assay/ZAP are single JSON objects; nuclei is JSONL (multiple objects,
        # so a whole-text parse fails -> nuclei). assay has tool=="assay" or a
        # "scan_result" key; ZAP has a top-level "site".
        try:
            obj = json.loads(head)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            if obj.get("tool") == "assay" or "scan_result" in obj:
                return "assay"
            if "site" in obj:
                return "zap"
        return "nuclei"
    if low.endswith(".jsonl") or low.endswith(".json"):
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

        Supported fmt: assay (JSON), nuclei (JSONL), nessus (.nessus XML),
        sarif (JSON), burp (issues XML), openvas (GVM XML), zap (JSON), or 'auto'.
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
