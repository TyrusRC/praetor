"""sync_workspace — reconcile a domain's .burp-intel files against findings.json.

findings.json is the source of truth (Rule 30). Everything else is derived and
can drift: a per-finding markdown writeup goes missing or stale, an orphan
writeup dir survives a deleted finding, coverage disagrees with what was actually
found, a checkpoint points at a finding that no longer exists. When a re-check
"says something different" there is otherwise no single place to re-align the
files — this is it.

`sync_workspace(domain, fix=True)`:
  - REGENERATES every finding's markdown projection from the canonical record
    (safe — projections are write-only derivations), and removes orphan writeup
    dirs whose finding is gone.
  - REPORTS (never silently mutates) the judgement-call drift: findings missing
    evidence, duplicate findings, MEDIUM+ findings with no impact string, and
    checkpoint/coverage references to findings that no longer exist.

Auto-fix is limited to deterministic regeneration; anything needing a decision is
surfaced for the operator, not guessed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._findings_io import _intel_dir, _load_findings_file, _safe_findings_path, _sanitized
from ._projection import remove_finding_projection, write_finding_projection


def _domain_dir(domain: str) -> Path:
    return _intel_dir() / _sanitized(domain)


def _fid(f: dict) -> str:
    return str(f.get("id") or f.get("finding_id") or "")


def _dedup_key(f: dict) -> tuple:
    return (
        str(f.get("endpoint", "")).lower().rstrip("/"),
        str(f.get("vuln_type") or f.get("category") or "").lower(),
        str(f.get("title", "")).lower().strip(),
        str(f.get("parameter", "")).lower(),
    )


def _has_evidence(f: dict) -> bool:
    ev = f.get("evidence")
    if not isinstance(ev, dict):
        return False
    if ev.get("proxy_history_index") not in (None, "", -1):
        return True
    return bool(ev.get("send_ref") or ev.get("collaborator_interaction_id")
                or ev.get("collaborator_id"))


_SEV_REPORTABLE = {"medium", "high", "critical"}


def reconcile(domain: str, fix: bool = True) -> dict[str, Any]:
    """Pure reconcile pass over a domain's workspace. Returns a structured report."""
    fpath = _safe_findings_path(domain)
    data = _load_findings_file(fpath)
    findings = data.get("findings", []) if isinstance(data, dict) else list(data)
    ddir = _domain_dir(domain)

    ids = {_fid(f) for f in findings if _fid(f)}
    regenerated: list[str] = []
    orphans: list[str] = []
    drift: list[str] = []

    # 1) Regenerate every projection from the canonical record.
    if fix:
        for f in findings:
            if _fid(f):
                write_finding_projection(domain, f)
                regenerated.append(_fid(f))

    # 2) Orphan writeup dirs (a findings/<id>/ with no matching finding).
    fdir = ddir / "findings"
    if fdir.is_dir():
        for sub in fdir.iterdir():
            if sub.is_dir() and sub.name not in ids:
                orphans.append(sub.name)
                if fix:
                    remove_finding_projection(domain, sub.name)

    # 3) Duplicate findings by dedup key.
    seen: dict[tuple, str] = {}
    for f in findings:
        k = _dedup_key(f)
        if k in seen:
            drift.append(f"DUPLICATE: {_fid(f)} shares (endpoint,type,title,param) "
                         f"with {seen[k]} — merge affected locations into one finding.")
        else:
            seen[k] = _fid(f)

    # 4) Findings missing evidence, or MEDIUM+ with no impact string.
    for f in findings:
        if str(f.get("status", "")).lower() in ("likely_false_positive",):
            continue
        if not _has_evidence(f):
            drift.append(f"NO EVIDENCE: {_fid(f)} has no proxy_history_index / "
                         f"send_ref / collaborator id — re-verify or delete.")
        if (str(f.get("severity", "")).lower() in _SEV_REPORTABLE
                and not str(f.get("impact", "")).strip()):
            drift.append(f"NO IMPACT: {_fid(f)} is {f.get('severity')} but impact "
                         f"is empty — the report omits its impact section.")

    # 5) checkpoint.json referencing findings that no longer exist.
    ckpt = ddir / "checkpoint.json"
    if ckpt.is_file():
        try:
            ck = json.loads(ckpt.read_text(encoding="utf-8"))
            blob = json.dumps(ck)
            for gone in [i for i in _referenced_ids(blob) if i not in ids]:
                drift.append(f"STALE CHECKPOINT: references finding {gone} which is "
                             f"not in findings.json — update next_action.")
        except (OSError, json.JSONDecodeError):
            pass

    # 6) coverage.json referencing findings that no longer exist.
    cov = ddir / "coverage.json"
    if cov.is_file():
        try:
            blob = cov.read_text(encoding="utf-8")
            for gone in [i for i in _referenced_ids(blob) if i not in ids]:
                drift.append(f"STALE COVERAGE: references finding {gone} not in "
                             f"findings.json.")
        except OSError:
            pass

    return {
        "domain": domain,
        "findings": len(findings),
        "in_sync": not drift and not orphans,
        "projections_regenerated": len(regenerated) if fix else 0,
        "orphans_removed": orphans if fix else [],
        "orphans_found": orphans,
        "drift": drift,
        "fixed": fix,
    }


_FID_RE = re.compile(r"\b(f\d{2,}|cred\d{2,}|finding[_-]?\d+)\b", re.IGNORECASE)


def _referenced_ids(blob: str) -> set[str]:
    return {m.group(0) for m in _FID_RE.finditer(blob)}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def sync_workspace(domain: str, fix: bool = True) -> str:
        """Reconcile a domain's .burp-intel files against the canonical findings.json.

        Run this when a re-check disagrees with stored state, after bulk edits, or
        on resume, to re-align every derived file with the source of truth.

        With fix=True (default) it REGENERATES each finding's markdown writeup and
        removes orphan writeup dirs (safe, deterministic). It then REPORTS the
        drift that needs a decision — duplicate findings, findings with no
        evidence, MEDIUM+ findings with an empty impact, and checkpoint/coverage
        references to findings that no longer exist — without guessing a fix.

        Args:
            domain: Target domain whose workspace to reconcile.
            fix: Regenerate projections + remove orphans (default True). False =
                report-only dry run.
        """
        r = reconcile(domain, fix=fix)
        lines = [
            f"sync_workspace({domain}) — {r['findings']} findings, "
            f"{'IN SYNC' if r['in_sync'] else 'DRIFT FOUND'}",
        ]
        if fix:
            lines.append(f"  regenerated {r['projections_regenerated']} writeup projection(s)")
            if r["orphans_removed"]:
                lines.append(f"  removed orphan writeups: {', '.join(r['orphans_removed'])}")
        elif r["orphans_found"]:
            lines.append(f"  orphan writeups (dry run): {', '.join(r['orphans_found'])}")
        if r["drift"]:
            lines.append(f"\n  {len(r['drift'])} item(s) need a decision (not auto-fixed):")
            lines.extend(f"    - {d}" for d in r["drift"])
        else:
            lines.append("  no judgement-call drift — findings, evidence, coverage, checkpoint agree.")
        return "\n".join(lines)
