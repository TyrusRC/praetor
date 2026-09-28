#!/usr/bin/env python3
"""SessionStart hook — enforce the Rule 20a recon gate without relying on memory.

A hook can't call MCP tools, but it CAN inject context. This scans .burp-intel/
for prior engagement state and, when any exists, reminds Claude to LOAD it
(load_target_intel + load_checkpoint) before testing — the single most-cited cause
of duplicate work and phantom-index citations is skipping that load. Token-lean
(names + one next-action line per domain) and fail-OPEN: any error injects
nothing rather than breaking the session.
"""
import json
import os
import sys
from pathlib import Path


def _intel_dir() -> Path | None:
    for root in (os.environ.get("CLAUDE_PROJECT_DIR"), os.getcwd()):
        if root:
            p = Path(root) / ".burp-intel"
            if p.is_dir():
                return p
    return None


def main() -> None:
    base = _intel_dir()
    if base is None:
        return  # new workspace — nothing to load, stay quiet
    lines: list[str] = []
    for dom in sorted(base.iterdir()):
        if not dom.is_dir() or dom.name.startswith("_"):
            continue
        fcount = 0
        fj = dom / "findings.json"
        if fj.is_file():
            try:
                data = json.loads(fj.read_text(encoding="utf-8"))
                items = data.get("findings", data) if isinstance(data, dict) else data
                fcount = len(items) if isinstance(items, list) else 0
            except (OSError, json.JSONDecodeError):
                pass
        nxt = ""
        ck = dom / "checkpoint.json"
        if ck.is_file():
            try:
                nxt = str(json.loads(ck.read_text(encoding="utf-8")).get("next_action", ""))[:120]
            except (OSError, json.JSONDecodeError):
                pass
        detail = f"{fcount} findings" + (f"; next: {nxt}" if nxt else "")
        lines.append(f"  - {dom.name} ({detail})")

    if not lines:
        return
    context = (
        "Prior Praetor engagement state is on disk (Rule 20a recon gate). BEFORE "
        "any testing on these domains, load it — do NOT re-crawl:\n"
        + "\n".join(lines[:12])
        + "\n  Run: load_target_intel(domain, 'all') + load_checkpoint(domain) + "
        "coverage_summary(domain). If a re-check disagrees with stored state, run "
        "sync_workspace(domain)."
    )
    json.dump({"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": context,
    }}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail-open: never break session start
    sys.exit(0)
