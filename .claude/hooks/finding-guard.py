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
import os
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


def _find_in(path: Path, fid: str):
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for f in store.get("findings", []):
        if f.get("id") == fid:
            return f
    return None


def _intel_bases():
    """.burp-intel roots to search, in priority order, de-duplicated.

    $CLAUDE_PROJECT_DIR (set by Claude Code at hook runtime) is the canonical
    project root; cwd is the fallback. Checking both means the guard still finds
    the store if the hook's cwd drifts from the MCP server's — a drift would
    otherwise make it silently ALLOW a flip, the one failure we can't accept.
    """
    bases = []
    for root in (os.environ.get("CLAUDE_PROJECT_DIR"), os.getcwd()):
        if not root:
            continue
        p = Path(root) / ".burp-intel"
        if p not in bases:
            bases.append(p)
    return bases


def _load_finding(domain: str, fid: str):
    """Best-effort lookup of a finding by id. Returns the dict or None.

    Reads the domain's own findings.json first (the cheap common path) and only
    globs sibling stores if that misses — no wasted directory scan on a hit.
    """
    fid = (fid or "").strip()
    if not fid:
        return None
    for base in _intel_bases():
        if domain:
            f = _find_in(base / _sanitized(domain) / "findings.json", fid)
            if f is not None:
                return f
        try:
            for p in sorted(base.glob("*/findings.json")):
                f = _find_in(p, fid)
                if f is not None:
                    return f
        except OSError:
            pass
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
        deny(f"finding-guard: {fid} LOCKED at '{cur}' (report freeze). Won't delete a "
             f"shipped finding. Surface it; {unlock} only if the operator approves.")
    new = str(ti.get("status", "")).lower()
    if new and new != cur:
        deny(f"finding-guard: {fid} LOCKED at '{cur}' (report freeze). Won't silently "
             f"change it to '{new}'. Surface it; {unlock} only if the operator approves.")
    return  # same status / no change -> allow


if __name__ == "__main__":
    main()
