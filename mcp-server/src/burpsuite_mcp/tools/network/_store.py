"""Persistence for the network lane: host/service inventory + tool-run evidence.

The inventory (`network.json`, at the domain root next to findings.json) is the
machine source of truth for discovered hosts/services. Each tool execution is
appended to `network/runs.jsonl` — the non-Burp evidence record a network-lane
finding cites in place of a Burp logger_index.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from burpsuite_mcp.tools.notes._helpers import (
    _findings_lock,
    _safe_findings_path,
    atomic_write_json,
)
from burpsuite_mcp.tools.workspace import ensure_workspace


def _domain_root(domain: str) -> Path:
    # Reuse the traversal-guarded resolver, then take the parent of findings.json.
    return _safe_findings_path(domain).parent


def _network_json(domain: str) -> Path:
    return _domain_root(domain) / "network.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_inventory(domain: str) -> dict:
    p = _network_json(domain)
    if not p.exists():
        return {"hosts": [], "last_updated": ""}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"hosts": [], "last_updated": ""}


def merge_inventory(domain: str, parsed: dict) -> dict:
    """Merge a fresh parse into the persisted inventory, keyed by IP.

    Ports are merged by (port, proto); a re-scan updates service/version rather
    than duplicating. Serialised under the findings lock so a concurrent scan
    on the same domain can't lose hosts.
    """
    ensure_workspace(domain)
    path = _network_json(domain)
    with _findings_lock(path):
        inv = load_inventory(domain)
        by_ip = {h["ip"]: h for h in inv.get("hosts", [])}
        for host in parsed.get("hosts", []):
            ip = host.get("ip")
            if not ip:
                continue
            existing = by_ip.get(ip)
            if existing is None:
                by_ip[ip] = host
                continue
            # Merge hostnames.
            names = set(existing.get("hostnames", [])) | set(host.get("hostnames", []))
            existing["hostnames"] = sorted(n for n in names if n)
            # Merge ports by (port, proto).
            pkey = {(p["port"], p["proto"]): p for p in existing.get("ports", [])}
            for p in host.get("ports", []):
                pkey[(p["port"], p["proto"])] = p
            existing["ports"] = sorted(pkey.values(), key=lambda p: (p["proto"], p["port"]))
        inv["hosts"] = sorted(by_ip.values(), key=lambda h: h["ip"])
        inv["last_updated"] = _now()
        atomic_write_json(path, inv, prefix=".network-")
    return inv


def record_run(domain: str, tool: str, target: str, argv: list[str],
               returncode: int, output_path: str, summary: str) -> str:
    """Record a tool run in the red-team operator log. Returns the oplog id.

    Delegates to the operator log (redteam/_oplog) so nmap/masscan evidence
    lands in the one place a red-team report and Ghostwriter forwarding read
    from — not a second ad-hoc ledger. ATT&CK technique auto-fills from `tool`.
    """
    from burpsuite_mcp.tools.redteam._oplog import record_action
    return record_action(
        domain, tool, " ".join(argv), description=summary, target=target,
        output_path=output_path, returncode=returncode,
    )


def write_tool_output(domain: str, filename: str, content: str) -> Path:
    """Persist raw tool output under material/tool-output/. Returns the path."""
    paths = ensure_workspace(domain)
    out = paths["tool_output"] / filename
    out.write_text(content, encoding="utf-8")
    return out

