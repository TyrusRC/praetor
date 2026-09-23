"""lock_finding / unlock_finding / lock_findings — freeze reported verdicts.

Report-integrity primitive. A LOCKED finding's reported verdict (status /
severity / impact) is immutable: a later re-test or re-save records the new
observation in `discrepancy_log` but does NOT change what a shipped report
states (enforced in `_findings_dedupe._dedupe_finding` and `retest._apply_retest`).

Call `lock_findings(domain)` when the operator confirms findings for a report so a
later re-ask cannot silently flip a status — the thing that makes a shipped report
stop matching the tool. The batch lock returns each finding with its evidence
index so the freeze is reviewable, not blind.
"""

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ._helpers import (
    _find_by_id,
    _load_findings_file,
    _safe_findings_path,
    _write_findings_file,
)


def _set_lock(finding: dict, locked: bool, *, reason: str = "", at: str = "") -> dict:
    """Pure: set/clear the lock fields on a finding dict."""
    if locked:
        finding["locked"] = True
        finding["locked_at"] = at
        if reason:
            finding["locked_reason"] = reason
    else:
        for k in ("locked", "locked_at", "locked_reason"):
            finding.pop(k, None)
    return finding


def _evidence_line(f: dict) -> str:
    """Pure: one reviewable line — id, severity, status, title, evidence index."""
    ev = f.get("evidence") or {}
    idx = (ev.get("proxy_history_index")
           or ev.get("collaborator_interaction_id") or "—")
    return (f"  {f.get('id', '?')} [{f.get('severity', '?')}] "
            f"{f.get('status', '?')} — {f.get('title', '')[:60]} (evidence: {idx})")


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def lock_finding(finding_id: str, domain: str, reason: str = "reported") -> str:
        """Freeze a finding's reported verdict so re-tests can't silently change it.

        A locked finding keeps its status/severity/impact; later observations go to
        discrepancy_log instead of overwriting. Use before shipping a report.
        """
        path = _safe_findings_path(domain)
        store = _load_findings_file(path)
        idx, f = _find_by_id(store.get("findings", []), finding_id)
        if f is None:
            return f"error: finding {finding_id!r} not found for {domain!r}"
        _set_lock(f, True, reason=reason,
                  at=datetime.now(timezone.utc).isoformat())
        store["findings"][idx] = f
        _write_findings_file(path, store)
        return (f"Locked {finding_id} at status='{f.get('status')}' (reason={reason}). "
                f"Reported verdict is frozen; re-tests log to discrepancy_log.")

    @mcp.tool()
    async def unlock_finding(finding_id: str, domain: str) -> str:
        """Unlock a finding so its reported verdict can change again.

        Do this only when the operator has decided to revise a shipped verdict.
        """
        path = _safe_findings_path(domain)
        store = _load_findings_file(path)
        idx, f = _find_by_id(store.get("findings", []), finding_id)
        if f is None:
            return f"error: finding {finding_id!r} not found for {domain!r}"
        _set_lock(f, False)
        store["findings"][idx] = f
        _write_findings_file(path, store)
        return f"Unlocked {finding_id}. Its status can change again on re-test/re-save."

    @mcp.tool()
    async def lock_findings(domain: str, status: str = "confirmed") -> str:
        """Batch-lock every finding of a status — a reviewable report freeze.

        Locks all findings currently at `status` (default confirmed) and lists each
        with its evidence index, so the operator gets a report snapshot that a later
        re-ask can no longer silently mutate. Call this when told to confirm/prepare
        findings for a report.
        """
        path = _safe_findings_path(domain)
        store = _load_findings_file(path)
        now = datetime.now(timezone.utc).isoformat()
        locked = []
        for f in store.get("findings", []):
            if str(f.get("status", "")).lower() == status.lower() and not f.get("locked"):
                _set_lock(f, True, reason="report-freeze", at=now)
                locked.append(f)
        _write_findings_file(path, store)
        if not locked:
            return f"No unlocked '{status}' findings to lock for {domain}."
        lines = [f"Locked {len(locked)} '{status}' finding(s) — report freeze:"]
        lines += [_evidence_line(f) for f in locked]
        lines.append("Each line shows its evidence index; these verdicts can no longer "
                     "flip silently. unlock_finding(<id>) to revise one.")
        return "\n".join(lines)
