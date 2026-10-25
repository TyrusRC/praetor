"""Scanner-output parsers: normalize each format's findings into Praetor dicts.

Each parse_* takes the raw export text and returns a list of finding dicts in
the _finding shape. _detect_format picks the parser for an 'auto' import. All
pure — no I/O, no Burp, no subprocess. Scanner output is untrusted input, so XML
is parsed with defusedxml (XXE / billion-laughs safe).
"""
from __future__ import annotations

import json
import re
from typing import Any

from defusedxml.ElementTree import fromstring as _xml_fromstring

from .._vuln_class import canonical


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


def parse_vigil(text: str) -> list[dict]:
    """vigil --json export -> finding dicts. Drops info/unknown severity.

    vigil emits one JSON object: {tool, scan_result: {findings: [...]}, ...}.
    Each finding carries `title`, `type` (canonical class), `confidence`,
    `tool` (which detector found it), WSTG/OWASP/CWE mappings, and
    optionally `remediation`, `references`, and `metadata`.
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
        klass = row.get("title") or row.get("type") or "finding"
        f = _finding(
            klass,
            sev,
            endpoint,
            "vigil",
            parameter=row.get("parameter") or "",
            evidence=row.get("description") or row.get("evidence") or row.get("request") or "",
        )
        confidence = str(row.get("confidence", "")).lower()
        if confidence in ("confirmed", "high", "medium", "low"):
            f["confidence"] = confidence
        # Carry OWASP mappings for praetor's coverage tracking
        for key in ("wstg", "owasp_top10", "api_top10", "cwe"):
            val = row.get(key)
            if val:
                f[key] = val
        # Carry the vigil detector name so praetor knows who found it
        tool = row.get("tool") or ""
        if tool:
            f["vigil_tool"] = tool
        # Carry remediation if present
        if row.get("remediation"):
            f["remediation"] = row["remediation"]
        out.append(f)
    return out


def parse_groma(text: str) -> list[dict]:
    """groma --format json export -> finding dicts. Drops info/unknown
    severity and the recon-only "open_port" type (that's inventory, not a
    finding — run_groma feeds it to merge_inventory separately, same as
    run_nmap).

    groma emits one JSON object: {tool: "groma", findings: [...], ...}. A
    finding's `type` is often a bare check id (a CVE id, "ftp_anonymous_
    login") rather than a class name, so — like parse_nessus's plugin-name
    handling — vuln_type slugifies from the human-readable `title`, not `type`.
    """
    out: list[dict] = []
    try:
        doc = json.loads(text)
    except ValueError:
        return out
    if doc.get("tool") != "groma":
        return out
    for row in doc.get("findings") or []:
        if row.get("type") == "open_port":
            continue
        sev = str(row.get("severity", "")).lower()
        if sev not in _REAL_SEV:
            continue
        host = row.get("host") or ""
        port = row.get("port") or ""
        endpoint = f"{host}:{port}" if port else host
        out.append(
            _finding(
                row.get("title") or row.get("type") or "finding",
                sev,
                endpoint,
                "groma",
                evidence=row.get("evidence") or row.get("description") or "",
            )
        )
    return out


_PARSERS = {
    "nuclei": parse_nuclei,
    "vigil": parse_vigil,
    "groma": parse_groma,
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
        # vigil/ZAP are single JSON objects; nuclei is JSONL (multiple objects,
        # so a whole-text parse fails -> nuclei). vigil has tool=="vigil" or a
        # "scan_result" key; ZAP has a top-level "site".
        try:
            obj = json.loads(head)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            if obj.get("tool") == "groma":
                return "groma"
            if obj.get("tool") == "vigil" or "scan_result" in obj:
                return "vigil"
            if "site" in obj:
                return "zap"
        return "nuclei"
    if low.endswith(".jsonl") or low.endswith(".json"):
        return "nuclei"
    return ""
