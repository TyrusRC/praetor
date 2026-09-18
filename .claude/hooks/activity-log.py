#!/usr/bin/env python3
"""PostToolUse activity log — append one compact line per state-changing tool call.

Auto-updating (no model action needed), SILENT (writes only to a file, never to
stdout, so it injects ZERO tokens into the model context), and append-only. It
exists so the operator can live-check progress (`tail -f .burp-intel/_activity.jsonl`)
and so multiple agents can cross-coordinate off ONE shared log without asking each
other. Fail-open: any error and it does nothing.

Logged tools are the meaningful STATE / decision events (findings, verdicts, locks,
checkpoints, intel saves) — not every probe — so the log stays a readable status
feed, not noise. Each line carries the session id so multi-agent activity is
distinguishable.
"""
import json
import os
import sys
import time
from pathlib import Path

# tool name -> short kind label. Only state/decision events.
LOG_TOOLS = {
    "mcp__praetor__save_finding": "finding",
    "mcp__praetor__record_retest": "retest",
    "mcp__praetor__lock_finding": "lock",
    "mcp__praetor__lock_findings": "lock",
    "mcp__praetor__unlock_finding": "unlock",
    "mcp__praetor__mark_finding_false_positive": "fp",
    "mcp__praetor__assess_finding": "assess",
    "mcp__praetor__write_checkpoint": "checkpoint",
    "mcp__praetor__save_target_intel": "intel",
    "mcp__praetor__save_finding_pipeline": "finding",
}


def _log_dir() -> Path:
    for root in (os.environ.get("CLAUDE_PROJECT_DIR"), os.getcwd()):
        if root:
            return Path(root) / ".burp-intel"
    return Path.cwd() / ".burp-intel"


def _note(resp) -> str:
    if isinstance(resp, str):
        s = resp
    elif isinstance(resp, dict):
        s = str(resp.get("result") or resp.get("error") or "")
    elif isinstance(resp, list) and resp:
        s = str(resp[0])
    else:
        s = ""
    return s.replace("\n", " ").strip()[:100]


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return
    kind = LOG_TOOLS.get(data.get("tool_name", ""))
    if not kind:
        return
    ti = data.get("tool_input", {}) or {}
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sid": str(data.get("session_id", ""))[:8],
        "kind": kind,
        "domain": ti.get("domain", "") or "",
        "id": ti.get("finding_id", "") or ti.get("phase", "") or "",
        "note": _note(data.get("tool_response")),
    }
    d = _log_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "_activity.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
    # No stdout -> transparent to the model, zero token cost.


if __name__ == "__main__":
    main()
