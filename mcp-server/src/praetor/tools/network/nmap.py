"""run_nmap — network host/service discovery on the non-Burp lane.

Traffic is TCP/UDP, not HTTP, so it bypasses Burp (bypass_proxy=True). Results
persist to the network inventory and each run is recorded as evidence. HTTP(S)
services found are bridged back to the web lane as scan candidates.

`nmap_scan()` is the structured core (returns a dict) used by both the run_nmap
MCP tool and the network pipeline; the tool just formats it.

Safety (HARD, both modes): destructive / brute NSE is refused (Rules 5-6).
Scope (HARD, mode-aware): strict blocks unknown targets; operator logs to
_audit.log and proceeds (operator owns SOW authorization, Rule 1a).
"""

from __future__ import annotations

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._guards import sanitize_target as _sanitize_target
from ._guards import scope_gate as _scope_gate
from ._nmap_parse import http_targets, parse_nmap_xml
from ._store import merge_inventory, record_run, write_tool_output

# NSE categories / script tokens that mutate state or brute-force — refused
# in BOTH engagement modes (Rules 5 and 6 are HARD and never relax).
_FORBIDDEN_NSE = ("dos", "brute", "broadcast", "exploit")
_FORBIDDEN_FLAGS = ("--script-args=unsafe=1", "unsafe=1")


def _check_nse_safety(flags: list[str]) -> str | None:
    joined = " ".join(flags).lower()
    for bad in _FORBIDDEN_FLAGS:
        if bad in joined:
            return f"refused: unsafe NSE arg ({bad}). Rules 5-6 are HARD."
    if "--script" in joined:
        for bad in _FORBIDDEN_NSE:
            if bad in joined:
                return (
                    f"refused: NSE category/script '{bad}' is destructive or brute-force "
                    "(Rules 5-6, HARD in both modes). Use safe categories: "
                    "default, safe, discovery, version, vuln."
                )
    return None


async def nmap_scan(
    target: str,
    domain: str = "",
    ports: str = "",
    flags: str = "-sV -Pn -T4",
    timeout: int = 600,
) -> dict:
    """Structured core: run nmap, persist, return a dict.

    Returns {ok, error, target, domain, parsed, inventory, http_targets,
    run_id, n_hosts, n_ports}. `error` is set (and ok=False) on any guard
    rejection / failure; the pipeline branches on it.
    """
    target, err = _sanitize_target(target)
    if err:
        return {"ok": False, "error": err, "target": target}

    flag_list = flags.split() if flags else []
    nse_err = _check_nse_safety(flag_list)
    if nse_err:
        return {"ok": False, "error": nse_err, "target": target}

    scope_err = _scope_gate(target)
    if scope_err:
        return {"ok": False, "error": scope_err, "target": target}

    if not _check_tool("nmap"):
        return {"ok": False, "error": "nmap not installed (sudo apt install nmap)",
                "target": target}

    resolved_domain = domain or target
    cmd = ["nmap", "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    cmd += flag_list + [target]

    stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    if rc != 0 and not stdout.strip().startswith("<?xml"):
        return {"ok": False, "error": f"nmap failed rc={rc}: {stderr.strip()[:300]}",
                "target": target}
    try:
        parsed = parse_nmap_xml(stdout)
    except ValueError as e:
        return {"ok": False, "error": f"nmap XML parse failed: {e}", "target": target}

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    try:
        out_path = write_tool_output(resolved_domain, f"nmap-{ts}.xml", stdout)
        inv = merge_inventory(resolved_domain, parsed)
        n_ports = sum(len(h["ports"]) for h in parsed["hosts"])
        run_id = record_run(resolved_domain, "nmap", target, cmd, rc, str(out_path),
                            f"{len(parsed['hosts'])} hosts, {n_ports} open ports")
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"nmap persistence failed: {e}", "target": target}

    return {
        "ok": True, "error": "", "target": target, "domain": resolved_domain,
        "parsed": parsed, "inventory": inv, "http_targets": http_targets(parsed),
        "run_id": run_id, "n_hosts": len(parsed["hosts"]), "n_ports": n_ports,
    }


def _format_scan(res: dict) -> str:
    if not res["ok"]:
        return f"nmap: {res['error']}"
    parsed, web = res["parsed"], res["http_targets"]
    lines = [
        f"nmap {res['target']} -> {res['n_hosts']} hosts up, {res['n_ports']} open ports "
        f"[run {res['run_id']}]",
        f"  inventory: {len(res['inventory']['hosts'])} hosts total in network.json",
    ]
    for host in parsed["hosts"][:25]:
        names = f" ({', '.join(host['hostnames'])})" if host["hostnames"] else ""
        lines.append(f"  {host['ip']}{names}:")
        for p in host["ports"][:40]:
            svc = "/".join(x for x in (p["service"], p["product"], p["version"]) if x)
            lines.append(f"    {p['port']}/{p['proto']} {p['state']} {svc}".rstrip())
    if web:
        lines.append("\n  Web-lane bridge — feed these into scope + the web lane:")
        for u in web[:30]:
            lines.append(f"    {u}")
        lines.append("  Next: configure_scope(keep_in_scope=[...]) -> browser_crawl / auto_probe")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_nmap(
        target: str,
        ports: str = "",
        flags: str = "-sV -Pn -T4",
        domain: str = "",
        timeout: int = 600,
    ) -> str:
        """Network host/service discovery (non-Burp lane). Persists an inventory
        and bridges discovered HTTP(S) services back to the web lane.

        Args:
            target: IP, CIDR (e.g. 10.10.11.0/24), or hostname. No shell metachars.
            ports: nmap -p value (e.g. '80,443,8080' or '1-1000'); blank = default.
            flags: nmap flags. Default '-sV -Pn -T4'. Destructive/brute NSE refused.
            domain: engagement key for .burp-intel/<domain>/ persistence.
            timeout: seconds (default 600).

        For a full chained sweep (discovery -> service enum -> leads) use
        run_network_recon instead.
        """
        return _format_scan(await nmap_scan(target, domain, ports, flags, timeout))

    @mcp.tool()
    async def get_network_inventory(domain: str, http_only: bool = False) -> str:
        """Show the persisted network inventory for a domain (network.json).

        Args:
            domain: engagement key.
            http_only: only list HTTP(S) services (the web-lane bridge set).
        """
        from ._store import load_inventory
        inv = load_inventory(domain)
        if not inv.get("hosts"):
            return f"No network inventory for {domain!r}. Run run_nmap / run_network_recon first."
        if http_only:
            urls = http_targets(inv)
            return "HTTP(S) services:\n" + ("\n".join(f"  {u}" for u in urls) or "  (none)")
        lines = [f"Network inventory for {domain} ({len(inv['hosts'])} hosts):"]
        for host in inv["hosts"]:
            names = f" ({', '.join(host['hostnames'])})" if host.get("hostnames") else ""
            lines.append(f"  {host['ip']}{names}: "
                         + ", ".join(f"{p['port']}/{p['proto']}" for p in host.get("ports", [])))
        return "\n".join(lines)
