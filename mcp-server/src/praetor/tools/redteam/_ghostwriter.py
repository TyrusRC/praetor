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


from ._gw_auth import *  # noqa: F401,F403
from ._gw_mappers import *  # noqa: F401,F403


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
                # mirror onto the Oplog timeline so the finding is visible there
                # too (tool contract: findings ride the timeline tagged vuln:/severity:)
                tl = await _gql(_INSERT_OPLOG_ENTRY, {"obj": map_finding_to_oplog(f)})
                if "error" in tl:
                    errors.append(f"finding {f['id']} timeline: {tl['error']}")
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

