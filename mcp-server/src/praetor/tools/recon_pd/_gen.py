"""ProjectDiscovery recon tool bodies (part 2: notify / CVE map / permutation).

Pure async implementations delegated to by the thin @mcp.tool() wrappers in
__init__.py. Helper functions (_not_installed / _parse_jsonl) live in
_shared.py; _check_tool / _run_cmd come from recon._common.
"""

from __future__ import annotations

import json

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._shared import _not_installed, _parse_jsonl


async def run_notify(message: str, provider: str = "", timeout: int = 30) -> str:
    if not _check_tool("notify"):
        return _not_installed("notify", "go install github.com/projectdiscovery/notify/cmd/notify@latest")
    cmd = ["notify", "-silent", "-bulk"]
    if provider:
        cmd += ["-provider", provider]
    # notify dispatches to Slack/Discord/etc — must NOT route through Burp.
    _out, err, rc = await _run_cmd(
        cmd, timeout=timeout, bypass_proxy=True, stdin_input=message.encode("utf-8"))
    if rc != 0:
        return f"notify failed [rc={rc}]: {err[:300]}"
    return f"notify: dispatched ({len(message)} bytes)" + (f" via {provider}" if provider else "")


async def run_vulnx(query: str = "", year: str = "", severity: str = "", timeout: int = 60) -> str:
    # vulnx takes a search-query DSL via a `search` subcommand.
    if not _check_tool("vulnx"):
        return _not_installed(
            "vulnx",
            "go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest")
    terms = []
    if query:
        terms.append(query)
    if severity:
        terms.append(f"severity:{severity.lower()}")
    if year:
        try:
            y = int(year)
            terms.append(f"cve_created_at:>={y} cve_created_at:<{y + 1}")
        except ValueError:
            terms.append(f"cve_created_at:>={year}")
    q = " ".join(terms) if terms else "is_kev:true"
    cmd = ["vulnx", "search", q, "--json", "--silent", "--limit", "30"]
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    rows = []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            rows = data.get("results") or []
    except (ValueError, TypeError):
        rows = []
    lines = [f"vulnx: {len(rows)} CVEs — query: {q}"]
    for r in rows[:30]:
        cve = r.get("cve_id", "?")
        sev = r.get("severity", "?")
        score = r.get("cvss_score", "")
        name = (r.get("name") or "")[:60]
        lines.append(f"  {cve} [{sev} {score}] {name}".rstrip())
    if not rows:
        blob = (err + out).lower()
        if "api key" in blob or "rate" in blob or "429" in blob:
            lines.append("Note: vulnx is rate-limited without a PDCP API key — "
                         "run `vulnx auth` or set PDCP_API_KEY.")
        elif rc != 0:
            lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_alterx(roots: list[str], pattern: str = "", timeout: int = 60) -> str:
    if not _check_tool("alterx"):
        return _not_installed("alterx", "go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
    if not roots:
        return "Error: roots list empty."
    cmd = ["alterx", "-silent"]
    for r in roots:
        cmd += ["-l", r]
    if pattern:
        cmd += ["-p", pattern]
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    hosts = [ln.strip() for ln in out.splitlines() if ln.strip()]
    lines = [f"alterx: {len(hosts)} permutations"]
    for h in hosts[:60]:
        lines.append(f"  {h}")
    if len(hosts) > 60:
        lines.append(f"  ... +{len(hosts) - 60} more")
    if rc != 0 and not hosts:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_chaos(domain: str, timeout: int = 60) -> str:
    import os
    if not _check_tool("chaos"):
        return _not_installed(
            "chaos",
            "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest  |  "
            "https://github.com/projectdiscovery/chaos-client",
        )
    if not os.environ.get("CHAOS_KEY"):
        return ("Error: CHAOS_KEY env var unset. Get a free key at "
                "https://cloud.projectdiscovery.io and `export CHAOS_KEY=...`")
    out, err, rc = await _run_cmd(
        ["chaos", "-d", domain, "-silent"],
        timeout=timeout, bypass_proxy=True,
    )
    hosts = sorted({line.strip() for line in out.splitlines() if line.strip()})
    lines = [f"chaos: {len(hosts)} subdomains for {domain}"]
    for h in hosts[:60]:
        lines.append(f"  {h}")
    if len(hosts) > 60:
        lines.append(f"  ... +{len(hosts) - 60} more")
    if rc != 0 and not hosts:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_dnsgen(wordlist_path: str, max_outputs: int = 5000, timeout: int = 120) -> str:
    if not _check_tool("dnsgen"):
        return _not_installed(
            "dnsgen",
            "pipx install dnsgen  |  https://github.com/AlephNullSK/dnsgen",
        )
    out, err, rc = await _run_cmd(
        ["dnsgen", wordlist_path],
        timeout=timeout, bypass_proxy=True,
    )
    perms = [ln.strip() for ln in out.splitlines() if ln.strip()]
    perms = perms[:max_outputs]
    lines = [f"dnsgen: {len(perms)} permutations from {wordlist_path}"]
    for p in perms[:40]:
        lines.append(f"  {p}")
    if len(perms) > 40:
        lines.append(f"  ... +{len(perms) - 40} more")
    if rc != 0 and not perms:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)


async def run_shuffledns(
    wordlist_path: str,
    domain: str = "",
    resolvers_path: str = "",
    mode: str = "bruteforce",
    timeout: int = 600,
) -> str:
    if not _check_tool("shuffledns"):
        return _not_installed(
            "shuffledns",
            "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest  |  "
            "https://github.com/projectdiscovery/shuffledns",
        )
    if not resolvers_path:
        return ("Error: shuffledns needs an explicit resolvers list "
                "(-r). Common: https://github.com/trickest/resolvers")
    if mode == "bruteforce":
        if not domain:
            return "Error: bruteforce mode needs domain."
        cmd = ["shuffledns", "-d", domain, "-w", wordlist_path,
               "-r", resolvers_path, "-mode", "bruteforce", "-silent"]
    elif mode == "resolve":
        cmd = ["shuffledns", "-list", wordlist_path,
               "-r", resolvers_path, "-mode", "resolve", "-silent"]
    else:
        return f"Error: mode must be bruteforce|resolve (got {mode!r})."
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    hosts = sorted({ln.strip() for ln in out.splitlines() if ln.strip()})
    lines = [f"shuffledns [{mode}]: {len(hosts)} resolved"]
    for h in hosts[:60]:
        lines.append(f"  {h}")
    if len(hosts) > 60:
        lines.append(f"  ... +{len(hosts) - 60} more")
    if rc != 0 and not hosts:
        lines.append(f"[rc={rc}] {err[:200]}")
    return "\n".join(lines)
