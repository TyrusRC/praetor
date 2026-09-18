#!/usr/bin/env python3
"""PreToolUse guard — protect a LOCKED (report-frozen) finding from silent re-verdict.

Separate from git-guard (which guards git). This enforces REPORT INTEGRITY at the
harness level so it does not depend on the model remembering: once findings are
locked for a report (lock_findings / lock_finding), refuse any tool call that would
flip OR delete a locked finding's verdict, and tell Claude to surface the
discrepancy and ask the operator instead.

Efficient + fail-OPEN: fires only on the finding-mutation tools, reads one JSON
file, and on any error/ambiguity it ALLOWS — it never blocks legitimate work.
"""
import json
import re
import sys
from pathlib import Path

STATUS_TOOLS = {"mcp__praetor__record_retest"}                # carries `status`
DELETE_TOOLS = {"mcp__praetor__mark_finding_false_positive"}  # deletes the finding


def deny(reason: str) -> None:
    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, sys.stdout)
    sys.exit(0)


def _sanitized(domain: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain or "").strip(".")


def _load_finding(domain: str, fid: str):
    """Best-effort lookup of a finding by id. Returns the dict or None."""
    fid = (fid or "").strip()
    if not fid:
        return None
    base = Path.cwd() / ".burp-intel"
    candidates = []
    if domain:
        candidates.append(base / _sanitized(domain) / "findings.json")
    try:
        candidates += sorted(base.glob("*/findings.json"))
    except OSError:
        pass
    for p in candidates:
        try:
            store = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for f in store.get("findings", []):
            if f.get("id") == fid:
                return f
    return None


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return  # fail open
    tool = data.get("tool_name", "")
    if tool not in STATUS_TOOLS and tool not in DELETE_TOOLS:
        return
    ti = data.get("tool_input", {}) or {}
    fid = ti.get("finding_id", "")
    domain = ti.get("domain", "")
    f = _load_finding(domain, fid)
    if not f or not f.get("locked"):
        return  # not a locked finding -> allow
    cur = str(f.get("status", "")).lower()
    unlock = f"unlock_finding('{fid}','{domain}')"
    if tool in DELETE_TOOLS:
        deny(f"BLOCKED by finding-guard: {fid} is LOCKED at status='{cur}' (report "
             f"freeze). Refusing to mark it false-positive / delete a shipped finding. "
             f"Surface this to the operator; run {unlock} only if they decide to revise.")
    new = str(ti.get("status", "")).lower()
    if new and new != cur:
        deny(f"BLOCKED by finding-guard: {fid} is LOCKED at status='{cur}' (report "
             f"freeze). Refusing to change it to '{new}' silently — a shipped report must "
             f"not drift. Surface the old-vs-new discrepancy to the operator; run {unlock} "
             f"only if they decide to revise the reported verdict.")
    return  # same status / no change -> allow


if __name__ == "__main__":
    main()
