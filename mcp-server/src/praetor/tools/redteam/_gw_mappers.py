"""Forward both lanes into Ghostwriter (central reporting/oplog hub):

- network operator-log actions -> `oplogEntry` (the activity timeline)
- web/Burp + network findings   -> `reportedFinding` (attached to a report, so
  they render in the deliverable and Ghostwriter's Findings tab) AND mirrored to
  `oplogEntry` tagged vuln:/severity: so findings are visible on the timeline too

Local .burp-intel stores stay authoritative; unset GHOSTWRITER_URL = no-op. A
per-domain marker prevents duplicate pushes.

NOTE: Hasura column names can drift between Ghostwriter versions — the mappings
here are validated against the installed instance. Re-check on upgrade.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from praetor import config
from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path

from ._oplog import read_oplog



_INSERT_OPLOG_ENTRY = (
    "mutation InsertOplogEntry($obj: oplogEntry_insert_input!) {"
    "  insert_oplogEntry_one(object: $obj) { id }"
    "}"
)
_INSERT_REPORTED_FINDING = (
    "mutation InsertReportedFinding($obj: reportedFinding_insert_input!) {"
    "  insert_reportedFinding_one(object: $obj) { id }"
    "}"
)

# Ghostwriter findingSeverity ids (default install) and findingType ids.
_SEVERITY_ID = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2,
                "INFO": 1, "INFORMATIONAL": 1}
_TYPE_WEB, _TYPE_NETWORK = 4, 1


def _finding_type_id(finding: dict) -> int:
    ep = (finding.get("endpoint") or "").lower()
    return _TYPE_WEB if ep.startswith("http") else _TYPE_NETWORK


def _evidence_ref(finding: dict) -> str:
    ev = finding.get("evidence") or {}
    if isinstance(ev, dict):
        if ev.get("logger_index") is not None:
            return f"Burp logger_index={ev['logger_index']}"
        if ev.get("proxy_history_index") is not None:
            return f"Burp proxy_index={ev['proxy_history_index']}"
        if ev.get("oplog_id"):
            return f"operator-log {ev['oplog_id']}"
    return ""


# Cached JWT minted from GHOSTWRITER_USERNAME/PASSWORD via the login action.
# Empty when a static admin-secret / API token is configured, or before first
# login. Re-minted automatically if a request comes back with an auth error.


def map_oplog_entry(entry: dict) -> dict:
    """Praetor operator-log entry -> Ghostwriter oplogEntry input.

    Field names verified against the live oplogEntry_insert_input schema: the FK
    is `oplog` (not oplogId); there is no `tags` column, so ATT&CK tags go into
    `extraFields` (jsonb). `entryIdentifier` carries the Praetor op id.
    """
    return {
        "oplog": config.GHOSTWRITER_OPLOG_ID,
        "startDate": entry.get("start", ""),
        "endDate": entry.get("end", ""),
        "sourceIp": entry.get("source", ""),
        "destIp": entry.get("target", ""),
        "tool": entry.get("tool", ""),
        "userContext": entry.get("user_context", ""),
        "command": entry.get("command", ""),
        "description": entry.get("description", ""),
        "output": entry.get("output", "") or entry.get("output_path", ""),
        "comments": _entry_comments(entry),
        "operatorName": entry.get("operator", "") or "praetor",
        "entryIdentifier": entry.get("id", ""),
        "extraFields": {
            "tags": entry.get("tags", []),
            "tactic": entry.get("tactic", ""),
            "technique": entry.get("technique", ""),
        },
    }


def _entry_comments(entry: dict) -> str:
    bits = []
    if entry.get("technique"):
        bits.append(f"ATT&CK {entry['technique']} {entry.get('technique_name','')}".strip())
    if entry.get("returncode") is not None:
        bits.append(f"rc={entry['returncode']}")
    if entry.get("detected"):
        bits.append("DETECTED by blue team")
    bits.append(f"praetor-oplog:{entry.get('id','')}")
    return " | ".join(bits)


def map_reported_finding(finding: dict, report_id: int) -> dict:
    """Praetor finding (web/Burp or network) -> Ghostwriter reportedFinding.

    Maps onto the finding's real report fields (impact / mitigation /
    replication / cvss), so it renders in the deliverable — not just the oplog.
    The evidence pointer (Burp logger_index or operator-log id) goes into
    `references` and `extraFields` for traceability back to the source lane.
    """
    ev_ref = _evidence_ref(finding)
    repro = finding.get("reproduction_steps") or []
    return {
        "reportId": report_id,
        "title": finding.get("title", "") or f"{finding.get('vuln_type','finding')}",
        "severityId": _SEVERITY_ID.get((finding.get("severity") or "").upper(), 3),
        "findingTypeId": _finding_type_id(finding),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", ""),
        "mitigation": finding.get("remediation", ""),
        "replication_steps": "\n".join(repro) if repro else finding.get("poc_request", ""),
        "affectedEntities": finding.get("endpoint", ""),
        "references": ev_ref,
        "cvssVector": finding.get("cvss4_vector", "") or finding.get("cvss_vector", ""),
        "extraFields": {
            "praetor_id": finding.get("id", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "evidence": ev_ref,
            "cwe": finding.get("cwe", ""),
        },
    }


def map_finding_to_oplog(finding: dict) -> dict:
    """Praetor finding -> Ghostwriter oplogEntry (activity-timeline mirror).

    A finding is pushed to `reportedFinding` (the deliverable) AND mirrored here
    so it is visible on the Oplog timeline tagged vuln:/severity: — the tool
    contract, and what makes web-lane findings (which create no operator-log
    action of their own) show up in the Oplog view at all.
    """
    sev = (finding.get("severity") or "").upper()
    vt = finding.get("vuln_type", "")
    ev_ref = _evidence_ref(finding)
    return {
        "oplog": config.GHOSTWRITER_OPLOG_ID,
        "tool": "praetor-finding",
        "destIp": finding.get("endpoint", ""),
        "userContext": vt,
        "command": finding.get("poc_request", "") or finding.get("title", ""),
        "description": finding.get("title", ""),
        "output": finding.get("impact", ""),
        "comments": " ".join(p for p in (f"vuln:{vt}" if vt else "",
                                          f"severity:{sev}" if sev else "", ev_ref) if p),
        "operatorName": finding.get("operator", "") or "praetor",
        "entryIdentifier": f"finding:{finding.get('id', '')}",
        "extraFields": {
            "tags": ["finding"] + ([f"severity:{sev}"] if sev else []) + ([f"vuln:{vt}"] if vt else []),
            "severity": sev,
            "evidence": ev_ref,
            "praetor_finding_id": finding.get("id", ""),
        },
    }



__all__ = ['_INSERT_OPLOG_ENTRY', '_INSERT_REPORTED_FINDING', '_SEVERITY_ID', '_finding_type_id', '_evidence_ref', 'map_oplog_entry', '_entry_comments', 'map_reported_finding', 'map_finding_to_oplog']
