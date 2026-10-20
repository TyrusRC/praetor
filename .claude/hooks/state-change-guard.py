#!/usr/bin/env python3
"""PreToolUse guard — Rule 8a: confirm destructive state-changes on raw send paths.

send_raw_request and curl_request are unrestricted operator-owned tools (they
bypass the confirm_* safety gates). This hook catches requests that would delete
accounts, change passwords, move money, or change privileges and asks the
operator to approve before sending.

Fail-OPEN: on any error or ambiguity it ALLOWS — it never blocks legitimate work.
False positives are acceptable (operator can approve); false negatives are the risk.
"""
import json
import re
import sys

_STATE_CHANGE_KEYWORDS = re.compile(
    r"\b(?:delete|remove|destroy|password|passwd|credential|transfer|payment"
    r"|withdraw|privilege|role|admin|deactivate|terminate|purge)\b",
    re.IGNORECASE,
)


def deny(reason: str) -> None:
    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, sys.stdout)
    sys.exit(0)


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return  # fail open
    ti = data.get("tool_input", {}) or {}

    haystack_parts = []
    for key in ("url", "path", "endpoint", "body", "data", "raw_request"):
        val = ti.get(key)
        if isinstance(val, str):
            haystack_parts.append(val)
    method = (ti.get("method") or "").upper()
    haystack = " ".join(haystack_parts)

    if method == "DELETE":
        deny("Rule 8a: DELETE method detected. Confirm with operator before sending.")
        return

    m = _STATE_CHANGE_KEYWORDS.search(haystack)
    if m:
        deny(f"Rule 8a: state-changing keyword '{m.group()}' detected. "
             "Confirm with operator before sending.")


if __name__ == "__main__":
    main()
