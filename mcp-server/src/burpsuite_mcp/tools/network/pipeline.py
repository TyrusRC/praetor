"""run_network_recon — the network lane's default loop, in one call:
discover (nmap) -> route per open service -> enumerate -> extract leads +
auto-loot -> bridge web services to the web lane. Only fitting/installed tools
run; covered (host, service, tool) tuples are skipped. Every step is logged.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._routing import extract_leads, extract_loot, is_web, plans_for
from .nmap import nmap_scan
from .run_tool import run_sanctioned

_DEPTH_FLAGS = {
    "quick": "-Pn -T4 --top-ports 100",
    "standard": "-sV -Pn -T4",
    "deep": "-sV -sC -Pn -T4 -p-",
}


def _covered_path(domain: str) -> Path:
    from ._store import ensure_workspace
    return ensure_workspace(domain)["network"] / "_enum_covered.json"


def _load_covered(domain: str) -> set:
    p = _covered_path(domain)
    if not p.exists():
        return set()
    try:
        return set(tuple(x) for x in json.loads(p.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError):
        return set()


def _save_covered(domain: str, covered: set) -> None:
    p = _covered_path(domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sorted(list(covered))), encoding="utf-8")


def _parse_creds(creds: str) -> tuple[str, str, str]:
    """'DOMAIN/user:password' -> (domain, user, password). Any part may be ''."""
    dom, rest = (creds.split("/", 1) + [""])[:2] if "/" in creds else ("", creds)
    user, pw = (rest.split(":", 1) + [""])[:2] if ":" in rest else (rest, "")
    return dom, user, pw


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_network_recon(
        target: str,
        domain: str = "",
        creds: str = "",
        depth: str = "standard",
        skip_covered: bool = True,
        timeout: int = 900,
    ) -> str:
        """Chained network kill-chain: discover -> route -> enumerate -> leads.

        The one-call entrypoint for the network lane. Scans the target, then for
        each open service automatically runs the enumeration tool that fits it
        (SMB->enum4linux-ng/nxc, LDAP->anon bind, RPC->null user enum, MSSQL,
        SNMP, ...), extracts leads (anon access, roastable hashes, SMB signing
        off, Pwn3d!), auto-loots hashes, and bridges HTTP(S) services to the web
        lane. Every step is recorded in the operator log with ATT&CK.

        Args:
            target: IP / CIDR / hostname.
            domain: engagement key (defaults to target).
            creds: 'DOMAIN/user:password' to unlock authenticated enum steps.
                Blank = unauthenticated foothold enum only.
            depth: 'quick' (top-100), 'standard' (-sV, default), 'deep' (-p- -sC).
            skip_covered: skip (host, service, tool) tuples already run this
                engagement (default True) — keeps re-runs fast.
            timeout: per-tool seconds (default 900 for the scan; enum steps 300).

        Returns a phased summary: hosts/services, enum runs (oplog ids), leads,
        loot captured, and the web_targets to push into the web lane.
        """
        resolved = domain or target
        depth = depth if depth in _DEPTH_FLAGS else "standard"

        # Phase 1: discovery (nmap_scan runs its own scope + safety gates).
        scan = await nmap_scan(target, resolved, flags=_DEPTH_FLAGS[depth], timeout=timeout)
        if not scan["ok"]:
            return f"run_network_recon: discovery failed — {scan['error']}"

        have_creds = bool(creds.strip())
        cdom, cuser, cpass = _parse_creds(creds)
        covered = _load_covered(resolved) if skip_covered else set()

        enum_runs: list[dict] = []
        leads: list[dict] = []
        loot_ids: list[str] = []
        skipped = 0

        # Phase 2-4: route + enumerate + leads, per host/service.
        for host in scan["parsed"]["hosts"]:
            ip = host["ip"]
            for port in host["ports"]:
                svc, pnum = port.get("service", ""), port.get("port", 0)
                if is_web(svc, pnum):
                    continue  # handled by the web-lane bridge
                for step in plans_for(svc, pnum, have_creds):
                    tool = step["tool"]
                    sig = (ip, svc, tool)
                    if skip_covered and sig in covered:
                        skipped += 1
                        continue
                    args = step["args"].format(ip=ip, domain=cdom, user=cuser,
                                               password=cpass, creds=creds)
                    res = await run_sanctioned(
                        tool, args, resolved, target=ip,
                        description=f"{step['why']} ({svc}/{pnum})", timeout=300)
                    covered.add(sig)
                    if not res["ok"]:
                        enum_runs.append({"ip": ip, "svc": svc, "tool": tool,
                                          "ok": False, "error": res["error"]})
                        continue
                    out = res["output"]
                    step_leads = extract_leads(out)
                    for ld in step_leads:
                        ld.update({"ip": ip, "svc": svc, "tool": tool, "oplog_id": res["oplog_id"]})
                    leads.extend(step_leads)
                    # Auto-loot with chain-of-custody back to this run.
                    from burpsuite_mcp.tools.redteam._oplog import record_loot
                    for ltype, val in extract_loot(out):
                        row = record_loot(resolved, ltype, val, source_host=ip,
                                          obtained_via=tool, oplog_id=res["oplog_id"])
                        loot_ids.append(row["id"])
                    enum_runs.append({"ip": ip, "svc": svc, "tool": tool,
                                      "ok": True, "oplog_id": res["oplog_id"]})

        if skip_covered:
            _save_covered(resolved, covered)

        return _format(target, resolved, depth, scan, enum_runs, leads, loot_ids,
                       skipped, have_creds)


def _format(target, domain, depth, scan, enum_runs, leads, loot_ids, skipped, have_creds) -> str:
    ok_runs = [r for r in enum_runs if r["ok"]]
    lines = [
        f"run_network_recon {target} [depth={depth}, "
        f"{'authenticated' if have_creds else 'unauth'}] domain={domain}",
        f"  discovery: {scan['n_hosts']} hosts, {scan['n_ports']} open ports",
        f"  enumeration: {len(ok_runs)} tool runs"
        + (f", {skipped} skipped (covered)" if skipped else "")
        + (f", {len(enum_runs) - len(ok_runs)} failed/unavailable" if len(enum_runs) > len(ok_runs) else ""),
    ]
    if leads:
        lines.append(f"\n  LEADS ({len(leads)}) — prioritise these:")
        for ld in leads[:30]:
            lines.append(f"    [{ld['type']}] {ld['ip']} {ld['svc']} ({ld['tool']}, {ld['oplog_id']}) — {ld['note']}")
    else:
        lines.append("\n  LEADS: none matched (review operator log; enum output saved)")
    if loot_ids:
        lines.append(f"\n  LOOT captured: {', '.join(loot_ids)} (get_operator_log(domain, 'loot'))")
    if scan["http_targets"]:
        lines.append("\n  WEB LANE — push these into scope, then browser_crawl / auto_probe:")
        for u in scan["http_targets"][:30]:
            lines.append(f"    {u}")
    # Next-action guidance = the kill-chain continuation.
    nxt = []
    if any(ld["type"] in ("asrep_hash", "kerberoast_hash", "ntlm_hash") for ld in leads):
        nxt.append("crack captured hashes: hashcat -m 18200/13100 (asrep/tgs)")
    if any(ld["type"] == "smb_signing_off" for ld in leads):
        nxt.append("SMB signing off -> ntlmrelayx relay chain")
    if any(ld["type"] in ("valid_cred", "admin_access") for ld in leads):
        nxt.append("valid creds -> re-run with creds='DOM/user:pass' for authenticated enum + bloodhound-python")
    if scan["http_targets"]:
        nxt.append("web services found -> configure_scope + auto_probe")
    if nxt:
        lines.append("\n  NEXT:")
        for n in nxt:
            lines.append(f"    - {n}")
    return "\n".join(lines)
