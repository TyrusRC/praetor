#!/usr/bin/env python3
"""PreCompact hook — persist-state reminder before context is compacted (Rule 31).

State that lives only in the conversation is lost at compaction: covered tuples
get re-tested and Burp indices get cited from memory. This injects a short
reminder to checkpoint and to keep indices in evidence, not in the prose the
summary will drop. Fail-OPEN.
"""
import json
import sys


def main() -> None:
    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreCompact",
        "additionalContext": (
            "About to compact (Rule 31). Before losing conversation state: ensure "
            "write_checkpoint(domain, phase=, round=, next_action=...) captured the "
            "COLD-executable next action, and that every Burp index you still need "
            "lives in evidence / reproductions[] / annotations — never recall an "
            "index from memory after compaction."
        ),
    }}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
