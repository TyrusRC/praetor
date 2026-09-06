"""ProjectDiscovery recon tool bodies (part 2: notify / CVE map / permutation).

Pure async implementations delegated to by the thin @mcp.tool() wrappers in
__init__.py. Helper functions (_not_installed / _parse_jsonl) live in
_shared.py; _check_tool / _run_cmd come from recon._common.
"""

from __future__ import annotations

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


async def run_mapcves(query: str = "", year: str = "", severity: str = "", timeout: int = 60) -> str:
    if not _check_tool("mapcves"):
        return _not_installed("mapcves", "go install github.com/projectdiscovery/mapcves@latest")
    cmd = ["mapcves", "-silent", "-json"]
    if query: cmd += ["-q", query]
    if year:  cmd += ["-y", year]
    if severity: cmd += ["-s", severity]
    out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    rows = _parse_jsonl(out)
    lines = [f"mapcves: {len(rows)} CVEs"]
    for r in rows[:30]:
        cve = r.get("cve_id") or r.get("id", "?")
        sev = r.get("severity", "?")
        tpl = r.get("nuclei_template") or r.get("template", "")
        lines.append(f"  {cve} [{sev}] {tpl}")
    if rc != 0 and not rows:
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
