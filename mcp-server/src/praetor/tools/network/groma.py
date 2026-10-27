"""run_groma — fast, full-port-range network/service vulnerability scanning.

Traffic is TCP, not HTTP, so it bypasses Burp (bypass_proxy=True). Results
persist to the SAME network inventory run_nmap feeds (network.json), and each
run is recorded as evidence. HTTP(S) services found are bridged back to the
web lane as scan candidates, same as run_nmap.

`groma_scan()` is the structured core (returns a dict) used by the run_groma
MCP tool; the tool just formats it.

groma (github.com/TyrusRC/groma) is Praetor's own standalone network scanner:
every TCP port by default — never a sampled top-N, which silently misses
services a narrow scan would never see — naabu-based service/version
fingerprinting when naabu is installed (falls back to groma's own
zero-dependency TCP-connect scanner otherwise, no fingerprinting then), and a
declarative YAML check library for known-CVE matching.

It fully replaces the old run_naabu wrapper (full port coverage, real service
fingerprinting, CVE checks — run_naabu had none of those) but does NOT
replace run_nmap: OS fingerprinting, NSE scripts, and scan-type-specific
firewall mapping (ACK/FIN/NULL/XMAS) are nmap-only and stay there.

Check findings (anything other than the recon-only "open_port" type) are
LEADS, not saved findings — Rule 13c treats a scanner hit the same way
regardless of which scanner produced it. Bring them into findings.json via
import_scan_results(fmt='groma') on the path this call returns, then
verify/assess/save per the normal pipeline.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._guards import sanitize_target as _sanitize_target
from ._guards import scope_gate as _scope_gate
from ._nmap_parse import http_targets
from ._store import merge_inventory, record_run, write_tool_output


def _groma_to_inventory(host: str, report: dict) -> dict:
    """Convert a groma JSON report's "open_port" findings into the same
    {"hosts": [...]} shape parse_nmap_xml produces, so merge_inventory /
    http_targets work unmodified regardless of which tool found the host.
    """
    ports = []
    for row in report.get("findings") or []:
        if row.get("type") != "open_port":
            continue
        ports.append({
            "port": row.get("port", 0),
            "proto": row.get("protocol", "") or "tcp",
            "state": "open",
            "service": row.get("service", "") or "",
            "product": row.get("product", "") or "",
            "version": row.get("version", "") or "",
            "tunnel": "",
        })
    ports.sort(key=lambda p: (p["proto"], p["port"]))
    hostnames: list[str] = []
    return {"hosts": [{"ip": host, "hostnames": hostnames, "ports": ports}]} if ports else {"hosts": []}


def _vuln_findings(report: dict) -> list[dict]:
    """Findings other than the recon-only "open_port" type — real check hits."""
    return [r for r in (report.get("findings") or []) if r.get("type") != "open_port"]


async def groma_scan(
    target: str,
    domain: str = "",
    ports: str = "",
    checks_dir: str = "",
    fast: bool = False,
    timeout: int = 300,
    rate: int = 0,
    concurrency: int = 0,
    fail_on: str = "",
) -> dict:
    """Structured core: run groma, persist, return a dict.

    Returns {ok, error, target, domain, parsed, inventory, http_targets,
    run_id, n_hosts, n_ports, vuln_findings, n_vuln_findings,
    tool_output_path, summary}. `error` is set (and ok=False) on any guard
    rejection / failure.
    """
    target, err = _sanitize_target(target)
    if err:
        return {"ok": False, "error": err, "target": target}

    scope_err = _scope_gate(target, tool="groma")
    if scope_err:
        return {"ok": False, "error": scope_err, "target": target}

    if not _check_tool("groma"):
        return {"ok": False, "error": "groma not installed. Build it: "
                "cd <groma repo> && go build -o ~/go/bin/groma ./cmd/groma",
                "target": target}

    resolved_domain = domain or target
    cmd = ["groma", "scan", target, "--format", "json", "--timeout", f"{timeout}s"]
    if ports:
        cmd += ["--ports", ports]
    if checks_dir:
        cmd += ["--checks", checks_dir]
    if fast:
        cmd.append("--fast")
    if rate and rate > 0:
        cmd += ["--rate", str(rate)]
    if concurrency and concurrency > 0:
        cmd += ["--concurrency", str(concurrency)]
    if fail_on:
        cmd += ["--fail-on", fail_on]

    # Give the subprocess a little longer than groma's own --timeout so the
    # process is not killed before it writes its report (same margin run_vigil
    # gives vigil).
    stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout + 30, bypass_proxy=True)
    if not stdout.strip():
        return {"ok": False, "error": f"groma produced no output (exit {rc}): {stderr.strip()[:300]}",
                "target": target}
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"groma produced no parseable JSON (exit {rc}). stderr: {stderr.strip()[:300]}",
                "target": target}

    parsed = _groma_to_inventory(target, report)
    vuln = _vuln_findings(report)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    try:
        out_path = write_tool_output(resolved_domain, f"groma-{ts}.json", stdout)
        inv = merge_inventory(resolved_domain, parsed)
        n_ports = sum(len(h["ports"]) for h in parsed["hosts"])
        run_id = record_run(resolved_domain, "groma", target, cmd, rc, str(out_path),
                             f"{len(parsed['hosts'])} hosts, {n_ports} open ports, "
                             f"{len(vuln)} check finding(s)")
    except (OSError, ValueError) as e:
        return {"ok": False, "error": f"groma persistence failed: {e}", "target": target}

    # Auto-bridge non-HTTP services to expedition listeners.
    expedition_bridges = await bridge_non_http_services(parsed)

    return {
        "ok": True, "error": "", "target": target, "domain": resolved_domain,
        "parsed": parsed, "inventory": inv, "http_targets": http_targets(parsed),
        "expedition_bridges": expedition_bridges,
        "run_id": run_id, "n_hosts": len(parsed["hosts"]), "n_ports": n_ports,
        "vuln_findings": vuln, "n_vuln_findings": len(vuln),
        "tool_output_path": str(out_path), "summary": report.get("summary", {}),
    }


# Non-HTTP services that expedition can relay and dissect.
_EXPEDITION_SERVICES: dict[str, list[int]] = {
    "redis": [6379],
    "mysql": [3306],
    "postgresql": [5432],
    "mongodb": [27017],
    "mqtt": [1883],
    "memcached": [11211],
    "dns": [53],
    "modbus": [502],
    "dnp3": [20000],
}

_SERVICE_NAME_MAP = {
    "redis": "redis", "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgresql", "postgres": "postgresql",
    "mongodb": "mongodb", "mongod": "mongodb",
    "mqtt": "mqtt", "mosquitto": "mqtt",
    "memcached": "memcached", "memcache": "memcached",
    "domain": "dns", "dns": "dns",
    "modbus": "modbus", "dnp3": "dnp3",
}


async def bridge_non_http_services(parsed: dict) -> list[dict]:
    """Auto-create expedition listeners for discovered non-HTTP services.

    Reads the parsed inventory and sets up a TCP relay for each known
    non-HTTP service so expedition captures all traffic for that protocol.
    Returns a list of {host, port, service, listener, status} dicts.
    """
    from praetor.tools.expedition import _client

    results = []
    for host_entry in parsed.get("hosts", []):
        ip = host_entry.get("ip", "")
        if not ip:
            continue
        for port_entry in host_entry.get("ports", []):
            port = port_entry.get("port", 0)
            svc_name = (port_entry.get("service", "") or "").lower()
            proto = (port_entry.get("proto", "") or "tcp").lower()

            # Match by service name or by well-known port
            matched_svc = _SERVICE_NAME_MAP.get(svc_name)
            if not matched_svc:
                for svc, known_ports in _EXPEDITION_SERVICES.items():
                    if port in known_ports:
                        matched_svc = svc
                        break
            if not matched_svc:
                continue

            listener_name = f"{matched_svc}-{ip}-{port}"
            # Bind to a high local port (30000 + original port offset)
            bind_port = 30000 + (port % 10000)

            resp = await _client.post("/listeners", json={
                "name": listener_name,
                "protocol": proto,
                "bind_host": "127.0.0.1",
                "bind_port": bind_port,
                "upstream_host": ip,
                "upstream_port": port,
            })

            status = "ok" if resp.get("ok") else resp.get("error", "unknown error")
            results.append({
                "host": ip, "port": port, "service": matched_svc,
                "listener": listener_name, "bind_port": bind_port, "status": status,
            })

    return results


def _format_scan(res: dict) -> str:
    if not res["ok"]:
        return f"groma: {res['error']}"
    parsed, web = res["parsed"], res["http_targets"]
    lines = [
        f"groma {res['target']} -> {res['n_hosts']} host(s), {res['n_ports']} open port(s), "
        f"{res['n_vuln_findings']} check finding(s) [run {res['run_id']}]",
        f"  inventory: {len(res['inventory']['hosts'])} hosts total in network.json",
    ]
    for host in parsed["hosts"]:
        lines.append(f"  {host['ip']}:")
        for p in host["ports"][:60]:
            svc = "/".join(x for x in (p["service"], p["product"], p["version"]) if x)
            lines.append(f"    {p['port']}/{p['proto']} open {svc}".rstrip())

    if res["vuln_findings"]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows = sorted(res["vuln_findings"],
                      key=lambda f: order.get(str(f.get("severity", "")).lower(), 5))
        lines.append("\n  Check findings — LEADS, not saved findings "
                      f"(import_scan_results(source={res['tool_output_path']!r}, "
                      f"domain={res['domain']!r}, fmt='groma') to bring into findings.json):")
        for f in rows[:30]:
            sev = str(f.get("severity", "?")).upper()
            name = f.get("title") or f.get("type") or "?"
            lines.append(f"    [{sev}] {name} — {f.get('host', '')}:{f.get('port', '')}")

    if web:
        lines.append("\n  Web-lane bridge — feed these into scope + the web lane:")
        for u in web[:30]:
            lines.append(f"    {u}")
        lines.append("  Next: configure_scope(keep_in_scope=[...]) -> browser_crawl / auto_probe")

    exp_bridges = res.get("expedition_bridges") or []
    ok_bridges = [b for b in exp_bridges if b["status"] == "ok"]
    if ok_bridges:
        lines.append(f"\n  Expedition bridge — {len(ok_bridges)} non-HTTP service(s) relayed:")
        for b in ok_bridges:
            lines.append(f"    {b['service']} {b['host']}:{b['port']} -> 127.0.0.1:{b['bind_port']} ({b['listener']})")
        lines.append("  Next: tcp_proxy_messages / tcp_repeat / tcp_fuzz to test these services")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_groma(
        target: str,
        domain: str = "",
        ports: str = "",
        checks_dir: str = "",
        fast: bool = False,
        timeout: int = 300,
        rate: int = 0,
        concurrency: int = 0,
        fail_on: str = "",
    ) -> str:
        """Network/service vulnerability scan via groma (non-Burp lane).

        Praetor's standalone network scanner: every TCP port by default
        (never a sampled top-N — a scanner that silently narrows coverage
        misses findings a full sweep would catch), naabu-based service/
        version fingerprinting when naabu is installed, and a declarative
        YAML check library for known-CVE matching. Persists an inventory
        (the same network.json run_nmap feeds) and bridges discovered
        HTTP(S) services back to the web lane.

        Complements, does NOT replace, run_nmap: OS fingerprinting, NSE
        scripts, and scan-type-specific firewall mapping (ACK/FIN/NULL/XMAS)
        are nmap-only. Use run_nmap for those; use run_groma for fast,
        exhaustive port coverage plus CVE-by-version matching.

        Check findings are LEADS, not saved findings (Rule 13c — a scanner
        hit needs replay/confirmation like any other). Call
        import_scan_results(source=<tool_output_path from this call's
        result>, domain=domain, fmt='groma') to bring them into findings.json
        as status='suspected', then verify/assess/save per the normal
        pipeline.

        Args:
            target: IP, CIDR, or hostname. No shell metachars.
            domain: engagement key for .burp-intel/<domain>/ persistence.
            ports: explicit nmap-format port list/range (e.g. '80,443' or
                '1-1000'); blank = every TCP port, 1-65535 (groma's default).
            checks_dir: directory of check YAML files to load and match.
                Blank = port/service discovery only, no CVE matching.
            fast: scan only a top-N ports subset instead of the full range
                (quicker, NOT exhaustive).
            timeout: seconds (default 300).
            rate: packets/sec rate limit (0 = naabu default).
            concurrency: worker concurrency (0 = auto, ulimit-aware).
            fail_on: CI gate — exit non-zero if finding >= this severity
                (critical/high/medium/low).
        """
        return _format_scan(await groma_scan(
            target, domain, ports, checks_dir, fast, timeout, rate, concurrency, fail_on,
        ))

    @mcp.tool()
    async def bridge_expedition_services(domain: str) -> str:
        """Set up expedition TCP listeners for non-HTTP services in the network inventory.

        Reads the saved inventory for a domain (from prior run_groma / run_nmap)
        and creates expedition relay listeners for every known non-HTTP service
        (Redis, MySQL, PostgreSQL, MongoDB, MQTT, Memcached, DNS, Modbus, DNP3).
        Use when services were already discovered and you want to intercept their
        traffic through expedition without re-scanning.

        Args:
            domain: engagement domain key (matches .burp-intel/<domain>/)
        """
        try:
            from ._store import load_inventory
            inv = load_inventory(domain)
        except Exception as e:
            return f"Error loading inventory for {domain}: {e}"
        if not inv or not inv.get("hosts"):
            return f"No inventory found for {domain}. Run run_groma or run_nmap first."

        bridges = await bridge_non_http_services(inv)
        if not bridges:
            return f"No non-HTTP services found in {domain} inventory."

        ok = [b for b in bridges if b["status"] == "ok"]
        failed = [b for b in bridges if b["status"] != "ok"]
        lines = [f"Expedition bridge: {len(ok)} listener(s) created, {len(failed)} failed."]
        for b in ok:
            lines.append(f"  {b['service']} {b['host']}:{b['port']} -> 127.0.0.1:{b['bind_port']}")
        for b in failed:
            lines.append(f"  FAILED {b['service']} {b['host']}:{b['port']}: {b['status']}")
        if ok:
            lines.append("\nNext: tcp_proxy_messages / tcp_repeat / tcp_fuzz to test these services.")
        return "\n".join(lines)
