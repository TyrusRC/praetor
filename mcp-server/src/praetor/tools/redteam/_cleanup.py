"""End-of-engagement cleanup reconciliation — "did we put everything back".

Reads the red-team operator log (`_oplog`) and surfaces the state-changing
actions whose effects outlive the test: a test account created, a config value
changed, a file dropped, a background process/service started, a listener
opened. Each becomes one checklist line the operator reconciles to baseline
before the engagement closes — the same discipline as a physical pentester
re-locking every door they propped.

This module only READS records of actions already taken and tracks whether each
has been reversed. It creates, plants, or generates nothing on any target.

The candidate categories correspond to the ATT&CK tactics in
`_oplog.ATTACK_MAP` whose effects persist — Persistence, Privilege Escalation,
Execution, Command and Control, Resource Development — plus the poisoning/relay
listener case that some tools log under Credential Access. Read-only tactics
(Discovery, most Credential Access) never surface. Reconciliation state is a
sidecar `.burp-intel/<domain>/network/cleanup.json` keyed by the oplog id, so
items stay checked off across calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from praetor.tools.notes._helpers import _findings_lock, atomic_write_json
from praetor.tools.workspace import ensure_workspace

from ._oplog import read_oplog

# ATT&CK technique ids (from _oplog.ATTACK_MAP) whose tactic leaves an artifact
# behind, grouped by the reconciliation category the operator has to work.
_ACCOUNT_TECH = {"T1098", "T1136"}              # Account Manipulation / Create Account
_FILE_TECH = {"T1105", "T1587.001"}             # Ingress Tool Transfer / dropped payload
_PROCESS_TECH = {"T1569.002", "T1053", "T1543", "T1134.002", "T1134.005"}
_LISTENER_TECH = {"T1090", "T1557.001"}         # Proxy / relay + poisoning listener

# Command-text fallback for actions logged with a bare or overridden technique.
# Matched case-insensitively against command + description, so the categoriser
# is not a hardcoded target list — it reads what the action actually did.
_ACCOUNT_KW = ("useradd", "adduser", "net user", "net1 user", "addcomputer",
               "changepasswd", "new-aduser", "samba-tool user", "bloodyad add")
_CONFIG_KW = ("reg add", "reg delete", "reg.exe", "setspn", "sysctl -w",
              "set-itemproperty", "bloodyad set", "config set", "gpo")
_FILE_KW = ("upload", "certutil -urlcache", "curl -o", "wget ", "iwr ",
            "invoke-webrequest", "smbclient", " put ", "copy \\\\", "scp ")
_PROCESS_KW = ("sc create", "sc.exe create", "schtasks", " at ", "systemctl",
               "nohup", "start-process", "psexec", "wmiexec", "smbexec",
               "service create")
_LISTENER_KW = ("responder", "ntlmrelayx", "chisel server", "ligolo", "socat",
                "nc -l", "ncat -l", "-lvnp", "krbrelayx", "listener")

_SUGGEST = {
    "account": "Delete the test account / revert the credential change and remove any group membership added.",
    "config": "Restore the original configuration value / registry key / directory attribute.",
    "file": "Delete the uploaded/dropped file from the target (and any operator-side implant generated for it).",
    "process": "Stop and remove the service / scheduled task / spawned background process on the host.",
    "listener": "Stop the listener / relay / proxy process and confirm the port it opened is closed.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _categorize(entry: dict) -> str | None:
    """Reconciliation category for one oplog entry, or None if read-only.

    Keyed off the recorded ATT&CK technique first, then a command-text
    fallback. Order is by specificity: listener before process, config before
    account (a `bloodyad set` attribute change is config, not an account add).
    """
    tech = (entry.get("technique") or "").strip()
    cmd = f"{entry.get('command', '')} {entry.get('description', '')}".lower()

    if tech in _LISTENER_TECH or any(k in cmd for k in _LISTENER_KW):
        return "listener"
    if tech in _PROCESS_TECH or any(k in cmd for k in _PROCESS_KW):
        return "process"
    if any(k in cmd for k in _CONFIG_KW):
        return "config"
    if tech in _ACCOUNT_TECH or any(k in cmd for k in _ACCOUNT_KW):
        return "account"
    if tech in _FILE_TECH or any(k in cmd for k in _FILE_KW):
        return "file"
    return None


def _where(entry: dict) -> str:
    """Best-effort location the artifact lives — host, then dropped path."""
    return entry.get("target") or entry.get("output_path") or entry.get("source") or ""


def _state_path(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "cleanup.json"


def _load_state(domain: str) -> dict:
    p = _state_path(domain)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def build_checklist(domain: str) -> dict:
    """Reconciliation checklist for a domain, merged with saved check-off state.

    One line per state-changing oplog action, keyed by its oplog id (the
    `item_id` to pass to `mark_reconciled`). Reconciled flag/evidence come from
    the sidecar so items persist across calls.
    """
    state = _load_state(domain)
    items = []
    for e in read_oplog(domain):
        category = _categorize(e)
        if not category:
            continue
        oid = e.get("id", "")
        st = state.get(oid, {})
        items.append({
            "item_id": oid,
            "category": category,
            "action": e.get("description") or e.get("command", ""),
            "command": e.get("command", ""),
            "where": _where(e),
            "tool": e.get("tool", ""),
            "technique": e.get("technique", ""),
            "logged_at": (e.get("start") or "")[:19],
            "suggested": _SUGGEST[category],
            "reconciled": bool(st.get("reconciled", False)),
            "evidence": st.get("evidence", ""),
        })
    reconciled = sum(1 for i in items if i["reconciled"])
    return {
        "domain": domain,
        "total": len(items),
        "reconciled": reconciled,
        "outstanding": len(items) - reconciled,
        "items": items,
    }


def mark_reconciled(domain: str, item_id: str, evidence: str = "") -> dict:
    """Flag one checklist line reconciled. Returns the updated tally or an error.

    `item_id` must be a live cleanup candidate (an oplog id that categorises),
    so an arbitrary or already-cleaned id cannot be marked by mistake.
    """
    if item_id not in {i["item_id"] for i in build_checklist(domain)["items"]}:
        return {"error": f"{item_id!r} is not an open cleanup item for {domain!r}. "
                         "Call get_cleanup_checklist to list valid item ids."}
    path = _state_path(domain)
    with _findings_lock(path):
        state = _load_state(domain)
        state[item_id] = {"reconciled": True, "evidence": evidence, "reconciled_at": _now()}
        atomic_write_json(path, state, prefix=".cleanup-")
    return {
        "item_id": item_id,
        "reconciled": True,
        "evidence": evidence,
        "outstanding": build_checklist(domain)["outstanding"],
    }
