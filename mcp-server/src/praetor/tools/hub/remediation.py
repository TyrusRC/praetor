"""Remediation lifecycle: owner, SLA due-date, aging, MTTR.

Praetor findings already carry `created` (ISO) + `status`. This adds the
remediation-tracking fields enterprise buyers expect — `owner`, `due_date`,
`remediation_status` (open|in_progress|resolved), `resolved_at` — and a
rollup (overdue / aging / MTTR) over them. Reuses `created` as first-seen.

`default_due_date` / `remediation_rollup` are pure; the @mcp.tools do I/O.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..report.lifecycle import load_intel

# Days-to-remediate SLA by severity. Overridable per call via sla_days.
SLA_DAYS: dict[str, int] = {"critical": 7, "high": 14, "medium": 30, "low": 90}
_REMEDIATION_STATES = {"open", "in_progress", "resolved"}


def _parse(iso: str) -> datetime | None:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def default_due_date(created_iso: str, severity: str, sla_days: int | None = None) -> str:
    """created + SLA(severity) days, as ISO. Falls back to 30d for unknown sev."""
    start = _parse(created_iso) or datetime.now(timezone.utc)
    days = sla_days if sla_days is not None else SLA_DAYS.get(str(severity).lower(), 30)
    return (start + timedelta(days=days)).isoformat()


def remediation_rollup(findings: list[dict], now_iso: str | None = None) -> dict[str, Any]:
    """Counts by remediation_status, overdue (past due & not resolved), MTTR."""
    now = _parse(now_iso) if now_iso else datetime.now(timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)

    counts = {"open": 0, "in_progress": 0, "resolved": 0, "untracked": 0}
    overdue = 0
    mttr_samples: list[float] = []

    for f in findings:
        state = str(f.get("remediation_status", "") or "").lower()
        if state not in _REMEDIATION_STATES:
            counts["untracked"] += 1
            continue
        counts[state] += 1

        if state == "resolved":
            created = _parse(f.get("created", ""))
            resolved = _parse(f.get("resolved_at", ""))
            if created and resolved:
                mttr_samples.append((resolved - created).total_seconds() / 86400)
        else:
            due = _parse(f.get("due_date", ""))
            if due and due < now:
                overdue += 1

    mttr = round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else None
    return {
        "total": len(findings),
        "open": counts["open"],
        "in_progress": counts["in_progress"],
        "resolved": counts["resolved"],
        "untracked": counts["untracked"],
        "overdue": overdue,
        "mttr_days": mttr,
    }


def _findings_path(domain: str) -> Path:
    return Path(".burp-intel") / domain / "findings.json"


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def set_remediation(
        domain: str,
        finding_id: str,
        owner: str = "",
        remediation_status: str = "",
        sla_days: int = 0,
    ) -> dict:
        """Attach remediation tracking to a finding: owner, SLA due-date, status.

        remediation_status: open | in_progress | resolved. Marking 'resolved'
        stamps resolved_at. due_date is derived from `created` + severity SLA
        (or sla_days) the first time the finding is tracked.
        """
        if remediation_status and remediation_status not in _REMEDIATION_STATES:
            return {"error": f"remediation_status must be one of {sorted(_REMEDIATION_STATES)}"}
        path = _findings_path(domain)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"error": f"no findings.json for '{domain}'"}

        findings = data.get("findings", [])
        target = next((f for f in findings if f.get("id") == finding_id), None)
        if target is None:
            return {"error": f"finding '{finding_id}' not found"}

        now = datetime.now(timezone.utc).isoformat()
        if owner:
            target["owner"] = owner
        if "due_date" not in target:
            target["due_date"] = default_due_date(
                target.get("created", now), target.get("severity", ""),
                sla_days or None,
            )
        elif sla_days:
            target["due_date"] = default_due_date(
                target.get("created", now), target.get("severity", ""), sla_days
            )
        if remediation_status:
            target["remediation_status"] = remediation_status
            if remediation_status == "resolved":
                target["resolved_at"] = now
        elif "remediation_status" not in target:
            target["remediation_status"] = "open"

        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return {
            "id": finding_id,
            "owner": target.get("owner", ""),
            "due_date": target.get("due_date"),
            "remediation_status": target.get("remediation_status"),
            "resolved_at": target.get("resolved_at"),
        }

    @mcp.tool()
    async def remediation_status(domain: str) -> dict:
        """Remediation rollup: open/in-progress/resolved, overdue count, MTTR (days)."""
        findings = load_intel(domain, "findings").get("findings", [])
        roll = remediation_rollup(findings)
        roll["overdue_findings"] = [
            {"id": f.get("id"), "severity": f.get("severity"), "due_date": f.get("due_date")}
            for f in findings
            if str(f.get("remediation_status", "")).lower() in {"open", "in_progress"}
            and (_parse(f.get("due_date", "")) or datetime.max.replace(tzinfo=timezone.utc))
            < datetime.now(timezone.utc)
        ]
        return roll
