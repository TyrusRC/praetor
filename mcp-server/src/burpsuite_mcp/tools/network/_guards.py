"""Shared HARD guards for the network lane (Rules 1, 5-9).

Target sanitisation and the scope gate live here so run_nmap and the generic
run_network_tool enforce them identically. Rules 5-9 stay HARD in both modes;
Rule 1 (scope) honours the engagement mode: strict blocks, operator logs + goes.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from burpsuite_mcp.tools import _scope_mode


def sanitize_target(target: str) -> tuple[str, str | None]:
    """Return (target, error). Accepts IP / CIDR / hostname; rejects shell
    metacharacters (argv is exec'd without a shell, but reject regardless)."""
    t = (target or "").strip()
    if not t:
        return t, "empty target"
    if any(c in t for c in (";", "|", "&", "`", "$", "\n", " ", "(", ")", "<", ">")):
        return t, f"illegal character in target {target!r}"
    try:
        ipaddress.ip_network(t, strict=False)
        return t, None
    except ValueError:
        pass
    if all(part and all(ch.isalnum() or ch in "-_." for ch in part) for part in t.split(".")):
        return t, None
    return t, f"target {target!r} is neither a valid IP/CIDR nor a hostname"


def scope_gate(target: str, tool: str = "nmap") -> str | None:
    """Honour engagement mode. strict -> block; operator -> audit-log + proceed."""
    mode = _scope_mode.get_mode()
    if mode == "strict":
        return (
            f"SCOPE (strict): network target {target!r} is not in a published scope. "
            "Network scope is not host/URL-based like the web lane — switch to "
            "configure_scope(mode='operator') if you own authorization (SOW/contract), "
            "then re-run."
        )
    try:
        audit = Path.cwd() / ".burp-intel" / "_audit.log"
        audit.parent.mkdir(parents=True, exist_ok=True)
        with audit.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "lane": "network", "tool": tool, "target": target, "mode": "operator",
            }) + "\n")
    except OSError:
        pass
    return None
