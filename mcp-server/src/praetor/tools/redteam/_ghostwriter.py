"""Forward both lanes into Ghostwriter (central reporting/oplog hub):

- network operator-log actions -> `oplogEntry` (the activity timeline)
- web/Burp + network findings   -> `reportedFinding` (attached to a report, so
  they render in the deliverable and Ghostwriter's Findings tab)

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


def is_configured() -> bool:
    return bool(config.GHOSTWRITER_URL and
               (config.GHOSTWRITER_API_TOKEN or config.GHOSTWRITER_ADMIN_SECRET) and
               config.GHOSTWRITER_OPLOG_ID)


def config_hint() -> str:
    missing = []
    if not config.GHOSTWRITER_URL:
        missing.append("GHOSTWRITER_URL")
    if not (config.GHOSTWRITER_API_TOKEN or config.GHOSTWRITER_ADMIN_SECRET):
        missing.append("GHOSTWRITER_API_TOKEN or GHOSTWRITER_ADMIN_SECRET")
    if not config.GHOSTWRITER_OPLOG_ID:
        missing.append("GHOSTWRITER_OPLOG_ID")
    return "set " + ", ".join(missing) if missing else "configured"


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if config.GHOSTWRITER_ADMIN_SECRET:
        h["X-Hasura-Admin-Secret"] = config.GHOSTWRITER_ADMIN_SECRET
    elif config.GHOSTWRITER_API_TOKEN:
        h["Authorization"] = f"Bearer {config.GHOSTWRITER_API_TOKEN}"
    return h


async def _gql(query: str, variables: dict) -> dict:
    """POST a GraphQL op. Returns {'data':...} or {'error':...}."""
    url = f"{config.GHOSTWRITER_URL}/v1/graphql"
    # Self-hosted Ghostwriter uses a self-signed cert on https://localhost.
    verify = not config.GHOSTWRITER_INSECURE_TLS
    try:
        async with httpx.AsyncClient(timeout=20, verify=verify) as c:
            r = await c.post(url, headers=_headers(),
                             json={"query": query, "variables": variables})
    except httpx.HTTPError as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text[:300]}"}
    body = r.json()
    if body.get("errors"):
        return {"error": "; ".join(e.get("message", "?") for e in body["errors"])}
    return {"data": body.get("data", {})}


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


async def _resolve_report_id() -> int | None:
    """Report to attach findings to: GHOSTWRITER_REPORT_ID, else the first
    report on the configured oplog's project, else a new report created there.
    Returns None if the project can't be resolved.
    """
    if config.GHOSTWRITER_REPORT_ID:
        return config.GHOSTWRITER_REPORT_ID
    oid = config.GHOSTWRITER_OPLOG_ID
    r = await _gql(f"{{ oplog(where:{{id:{{_eq:{oid}}}}}){{ projectId }} }}", {})
    rows = (r.get("data") or {}).get("oplog") or []
    if not rows:
        return None
    pid = rows[0]["projectId"]
    r2 = await _gql(f"{{ report(where:{{projectId:{{_eq:{pid}}}}}, limit:1){{ id }} }}", {})
    reps = (r2.get("data") or {}).get("report") or []
    if reps:
        return reps[0]["id"]
    r3 = await _gql(
        "mutation($p: bigint!, $t: String!) {"
        "  insert_report_one(object:{projectId:$p, title:$t}) { id } }",
        {"p": pid, "t": "Praetor Findings"})
    return ((r3.get("data") or {}).get("insert_report_one") or {}).get("id")


# ── sync marker (avoid duplicate pushes) ──────────────────────────────────
def _marker_path(domain: str) -> Path:
    return _safe_findings_path(domain).parent / "network" / "_ghostwriter_synced.json"


def _load_marker(domain: str) -> dict:
    p = _marker_path(domain)
    if not p.exists():
        return {"oplog": [], "findings": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"oplog": [], "findings": []}


def _save_marker(domain: str, marker: dict) -> None:
    p = _marker_path(domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(marker), encoding="utf-8")


async def sync(domain: str, what: str = "all") -> dict:
    """Push unsynced operator-log entries and/or findings into Ghostwriter.

    Returns a summary dict: pushed counts, skipped (already synced), errors.
    """
    if not is_configured():
        return {"error": f"Ghostwriter not configured — {config_hint()}"}

    marker = _load_marker(domain)
    pushed = {"oplog": 0, "findings": 0}
    errors: list[str] = []

    if what in ("all", "oplog"):
        synced = set(marker.get("oplog", []))
        for entry in read_oplog(domain):
            eid = entry.get("id")
            if not eid or eid in synced:
                continue
            res = await _gql(_INSERT_OPLOG_ENTRY, {"obj": map_oplog_entry(entry)})
            if "error" in res:
                errors.append(f"oplog {eid}: {res['error']}")
                break  # stop on first error; likely auth/schema — don't hammer
            synced.add(eid)
            pushed["oplog"] += 1
        marker["oplog"] = sorted(synced)

    if what in ("all", "findings"):
        synced = set(marker.get("findings", []))
        fpath = _safe_findings_path(domain)
        findings = _load_findings_file(fpath).get("findings", []) if fpath.exists() else []
        pending = [f for f in findings
                   if f.get("id") and f["id"] not in synced
                   and f.get("status") not in ("likely_false_positive", "stale")]
        report_id = await _resolve_report_id() if pending else None
        if pending and not report_id:
            errors.append("findings: could not resolve a Ghostwriter report "
                          "(set GHOSTWRITER_REPORT_ID or GHOSTWRITER_OPLOG_ID on a project)")
        else:
            for f in pending:
                res = await _gql(_INSERT_REPORTED_FINDING,
                                 {"obj": map_reported_finding(f, report_id)})
                if "error" in res:
                    errors.append(f"finding {f['id']}: {res['error']}")
                    break
                synced.add(f["id"])
                pushed["findings"] += 1
        marker["findings"] = sorted(synced)

    _save_marker(domain, marker)
    return {"pushed": pushed, "errors": errors,
            "synced_total": {"oplog": len(marker.get("oplog", [])),
                             "findings": len(marker.get("findings", []))}}


# ── BloodHound attack-path findings -> reportedFinding ─────────────────────
# Kept separate from findings.json (the web-lane save-finding board): AD
# attack-path edges are network-lane evidence and must not pollute the web
# findings store. Own marker file so re-runs don't double-insert.
def _bh_marker_path(domain: str) -> Path:
    return _safe_findings_path(domain).parent / "network" / "_ghostwriter_bloodhound.json"


def _load_bh_marker(domain: str) -> list[str]:
    p = _bh_marker_path(domain)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _save_bh_marker(domain: str, ids: list[str]) -> None:
    p = _bh_marker_path(domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sorted(set(ids))), encoding="utf-8")


async def sync_bloodhound_findings(domain: str, findings: list[dict]) -> dict:
    """Push BloodHound-derived attack-path findings to the Ghostwriter report.

    Each finding must carry a stable `id` (used for idempotency). Returns
    {pushed, skipped, errors}. Reuses the report-resolution + finding mapper.
    """
    if not is_configured():
        return {"error": f"Ghostwriter not configured — {config_hint()}"}
    synced = set(_load_bh_marker(domain))
    pending = [f for f in findings if f.get("id") and f["id"] not in synced]
    if not pending:
        return {"pushed": 0, "skipped": len(findings), "errors": []}
    report_id = await _resolve_report_id()
    if not report_id:
        return {"pushed": 0, "skipped": 0,
                "errors": ["could not resolve a Ghostwriter report "
                           "(set GHOSTWRITER_REPORT_ID or GHOSTWRITER_OPLOG_ID on a project)"]}
    pushed, errors = 0, []
    for f in pending:
        res = await _gql(_INSERT_REPORTED_FINDING, {"obj": map_reported_finding(f, report_id)})
        if "error" in res:
            errors.append(f"{f['id']}: {res['error']}")
            break
        synced.add(f["id"])
        pushed += 1
    _save_bh_marker(domain, list(synced))
    return {"pushed": pushed, "skipped": len(findings) - len(pending), "errors": errors}
