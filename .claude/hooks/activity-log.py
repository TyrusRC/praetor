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
from urllib.parse import urlparse

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
}

# confirm_*/escalate_* PoC tools: every call is a real attempt against a real
# target, pass or fail. Logging it is what makes "did you already test X" a
# question the log answers instead of one memory has to answer — the whole
# point of this hook. Each one returns a VerdictResult dict (verdict/
# confidence/evidence_summary/logger_indices), handled by _note() below.
_POC_TOOLS = (
    "confirm_cache_deception", "confirm_email_injection", "confirm_exposed_sourcemap",
    "confirm_expression", "confirm_idor", "confirm_ldap", "confirm_nosql",
    "confirm_padding_oracle", "confirm_race_condition", "confirm_rce",
    "confirm_second_order", "confirm_sqli", "confirm_ssi", "confirm_ssrf",
    "confirm_ssti", "confirm_xpath", "confirm_xslt", "confirm_xss", "confirm_xxe",
    "escalate_idor", "escalate_lfi", "escalate_open_redirect",
    "escalate_prototype_pollution", "escalate_sqli", "escalate_ssrf",
    "escalate_ssti", "escalate_xxe",
)
for _t in _POC_TOOLS:
    LOG_TOOLS[f"mcp__praetor__{_t}"] = "poc"


def _log_dir() -> Path:
    for root in (os.environ.get("CLAUDE_PROJECT_DIR"), os.getcwd()):
        if root:
            return Path(root) / ".burp-intel"
    return Path.cwd() / ".burp-intel"


def _note(resp) -> str:
    if isinstance(resp, str):
        s = resp
    elif isinstance(resp, dict) and "verdict" in resp:
        # VerdictResult (confirm_*/escalate_*): verdict + confidence + the
        # evidence index are what "did I already run this, and what happened"
        # needs — far more useful here than a generic result/error fallback.
        idx = resp.get("logger_indices") or resp.get("proxy_indices") or []
        s = (f"{resp['verdict']} conf={resp.get('confidence', '?')} "
             f"vuln={resp.get('vuln_type', '?')} idx={idx} "
             f"{resp.get('evidence_summary', '')}")
    elif isinstance(resp, dict):
        s = str(resp.get("result") or resp.get("error") or "")
    elif isinstance(resp, list) and resp:
        s = str(resp[0])
    else:
        s = ""
    return s.replace("\n", " ").strip()[:160]


def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return
    kind = LOG_TOOLS.get(data.get("tool_name", ""))
    if not kind:
        return
    ti = data.get("tool_input", {}) or {}
    # confirm_*/escalate_* take endpoint+parameter, not domain/finding_id —
    # derive both from the endpoint so a PoC call lands in the log the same
    # way a save_finding/checkpoint call does.
    domain = ti.get("domain", "") or (_hostname(ti.get("endpoint", "")) if kind == "poc" else "")
    ident = ti.get("finding_id", "") or ti.get("phase", "") or ti.get("parameter", "")
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sid": str(data.get("session_id", ""))[:8],
        "kind": kind,
        "domain": domain,
        "id": ident,
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
