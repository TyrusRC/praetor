"""ProjectDiscovery recon suite + graphw00f bridge.

Thin wrappers around OSS binaries. Each tool returns 'not installed'
diagnostics with install hint when the binary is absent; otherwise emits
parsed summary.

Tools:
    run_dnsx       DNS resolver / bruteforcer (PD)
    run_naabu      SYN/CONNECT port scanner (PD)
    run_tlsx       TLS metadata grab (PD)
    run_asnmap     ASN -> CIDR expansion (PD)
    run_uncover    Shodan/Censys/Fofa/Quake/Hunter wrapper (PD)
    run_cloudlist  Cloud asset inventory (PD)
    run_notify     Slack/Discord/Teams notifier (PD)
    run_mapcves    CVE -> exploit / nuclei template (PD)
    run_cdncheck   CDN / WAF / cloud-IP classifier (PD)
    run_alterx     Subdomain permutation generator (PD)
    run_graphw00f  GraphQL engine fingerprint
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _not_installed(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def _parse_jsonl(out: str) -> list[dict]:
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_dnsx(
        targets: list[str],
        record_type: str = "a",
        bruteforce_wordlist: str = "",
        timeout: int = 120,
    ) -> str:
        """Resolve / brute-force DNS records.

        Args:
            targets: list of domains.
            record_type: a|aaaa|cname|mx|txt|ns|soa|ptr.
            bruteforce_wordlist: optional path to wordlist for subdomain brute.
            timeout: seconds.
        """
        if not _check_tool("dnsx"):
            return _not_installed("dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        if not targets:
            return "Error: targets list empty."
        cmd = ["dnsx", "-silent", "-json", "-resp", "-" + record_type.lower()]
        if bruteforce_wordlist:
            cmd += ["-w", bruteforce_wordlist]
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(targets))
            inp = fh.name
        try:
            cmd += ["-l", inp]
            out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        finally:
            try: pathlib.Path(inp).unlink()
            except OSError: pass
        rows = _parse_jsonl(out)
        lines = [f"dnsx: {len(rows)} resolved ({record_type.upper()})"]
        for r in rows[:50]:
            lines.append(f"  {r.get('host','?')} -> {','.join(r.get(record_type, []))[:120]}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_naabu(target: str, ports: str = "top-100", timeout: int = 300) -> str:
        """Port scan via naabu.

        Args:
            target: host / IP / CIDR.
            ports: 'top-100' | 'top-1000' | 'full' | '80,443,8080'.
            timeout: seconds.
        """
        if not _check_tool("naabu"):
            return _not_installed("naabu", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        cmd = ["naabu", "-host", target, "-silent", "-json"]
        if ports == "top-100":
            cmd += ["-top-ports", "100"]
        elif ports == "top-1000":
            cmd += ["-top-ports", "1000"]
        elif ports == "full":
            cmd += ["-p", "-"]
        else:
            cmd += ["-p", ports]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        rows = _parse_jsonl(out)
        lines = [f"naabu: {len(rows)} open ports on {target}"]
        for r in rows[:60]:
            lines.append(f"  {r.get('host','?')}:{r.get('port','?')}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_tlsx(targets: list[str], timeout: int = 120) -> str:
        """Grab TLS metadata (SAN, JARM, cipher, expiry) via tlsx.

        Args:
            targets: list of host:port (default 443).
            timeout: seconds.
        """
        if not _check_tool("tlsx"):
            return _not_installed("tlsx", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")
        if not targets:
            return "Error: targets list empty."
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(targets))
            inp = fh.name
        try:
            out, err, rc = await _run_cmd(
                ["tlsx", "-l", inp, "-silent", "-json", "-san", "-cn", "-jarm", "-expired"],
                timeout=timeout, bypass_proxy=True,
            )
        finally:
            try: pathlib.Path(inp).unlink()
            except OSError: pass
        rows = _parse_jsonl(out)
        lines = [f"tlsx: {len(rows)} certs"]
        for r in rows[:30]:
            host = r.get("host", "")
            cn = r.get("subject_cn") or r.get("cn") or ""
            jarm = r.get("jarm_hash", "")[:30]
            sans = ",".join((r.get("subject_an") or [])[:5])
            lines.append(f"  {host}  cn={cn}  jarm={jarm}  san={sans}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_asnmap(target: str, timeout: int = 60) -> str:
        """Expand ASN / org / IP / domain to CIDR ranges.

        Args:
            target: 'AS13335' | 'cloudflare' | '1.1.1.1' | 'example.com'.
            timeout: seconds.
        """
        if not _check_tool("asnmap"):
            return _not_installed("asnmap", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
        flag = "-d"
        t = target.strip()
        if t.upper().startswith("AS") and t[2:].isdigit():
            flag = "-a"
        elif t.replace(".", "").isdigit():
            flag = "-i"
        out, err, rc = await _run_cmd(
            ["asnmap", flag, t, "-silent", "-json"], timeout=timeout, bypass_proxy=True,
        )
        rows = _parse_jsonl(out)
        lines = [f"asnmap: {len(rows)} ranges for {target}"]
        for r in rows[:30]:
            cidrs = ",".join(r.get("ranges") or r.get("range") or [])[:120]
            org = r.get("org", "")
            lines.append(f"  AS{r.get('asn','?')} {org}  {cidrs}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_uncover(query: str, engine: str = "shodan", limit: int = 50, timeout: int = 60) -> str:
        """Query Shodan / Censys / Fofa / Quake / Hunter / Netlas / CriminalIP via uncover.

        Args:
            query: search query (engine-specific syntax).
            engine: shodan | censys | fofa | quake | hunter | netlas | criminalip | zoomeye.
            limit: max results.
            timeout: seconds.
        """
        if not _check_tool("uncover"):
            return _not_installed("uncover", "go install github.com/projectdiscovery/uncover/cmd/uncover@latest")
        out, err, rc = await _run_cmd(
            ["uncover", "-q", query, "-e", engine, "-l", str(limit), "-silent"],
            timeout=timeout, bypass_proxy=True,
        )
        hosts = [ln.strip() for ln in out.splitlines() if ln.strip()]
        lines = [f"uncover [{engine}]: {len(hosts)} hits for {query!r}"]
        for h in hosts[:limit]:
            lines.append(f"  {h}")
        if rc != 0 and not hosts:
            lines.append(f"[rc={rc}] {err[:200]} (API key required for most engines)")
        return "\n".join(lines)

    @mcp.tool()
    async def run_cloudlist(provider: str = "", timeout: int = 300) -> str:
        """Inventory cloud assets via cloudlist.

        Args:
            provider: '' (all configured) | aws | azure | gcp | digitalocean | scaleway | linode | hetzner | namecheap | terraform.
            timeout: seconds.
        """
        if not _check_tool("cloudlist"):
            return _not_installed("cloudlist", "go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest")
        cmd = ["cloudlist", "-silent", "-json"]
        if provider:
            cmd += ["-provider", provider]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        rows = _parse_jsonl(out)
        lines = [f"cloudlist: {len(rows)} assets" + (f" [{provider}]" if provider else "")]
        for r in rows[:40]:
            lines.append(f"  {r.get('provider','?')} {r.get('host') or r.get('ip') or '?'}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]} (provider config required at ~/.config/cloudlist/config.yaml)")
        return "\n".join(lines)

    @mcp.tool()
    async def run_notify(message: str, provider: str = "", timeout: int = 30) -> str:
        """Pipe a message to Slack / Discord / Teams / Telegram / Pushover / email via notify.

        Args:
            message: text body.
            provider: '' (all configured) | slack | discord | teams | telegram | pushover | smtp.
            timeout: seconds.
        """
        if not _check_tool("notify"):
            return _not_installed("notify", "go install github.com/projectdiscovery/notify/cmd/notify@latest")
        cmd = ["notify", "-silent", "-bulk"]
        if provider:
            cmd += ["-provider", provider]
        import asyncio, os
        resolved = cmd[0]
        env = os.environ.copy()
        env["GODEBUG"] = "netdns=cgo"
        proc = await asyncio.create_subprocess_exec(
            resolved, *cmd[1:], stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=message.encode("utf-8")), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return "Error: notify timed out."
        if proc.returncode != 0:
            return f"notify failed [rc={proc.returncode}]: {stderr.decode(errors='replace')[:300]}"
        return f"notify: dispatched ({len(message)} bytes)" + (f" via {provider}" if provider else "")

    @mcp.tool()
    async def run_mapcves(query: str = "", year: str = "", severity: str = "", timeout: int = 60) -> str:
        """Query mapcves (CVE -> exploit / nuclei template).

        Args:
            query: free-text query (e.g. 'log4j', 'apache').
            year: filter by CVE year (e.g. '2024').
            severity: low|medium|high|critical.
            timeout: seconds.
        """
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

    @mcp.tool()
    async def run_cdncheck(targets: list[str], timeout: int = 60) -> str:
        """Classify CDN / WAF / cloud IP via cdncheck.

        Args:
            targets: list of hosts/IPs.
            timeout: seconds.
        """
        if not _check_tool("cdncheck"):
            return _not_installed("cdncheck", "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest")
        if not targets:
            return "Error: targets list empty."
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(targets))
            inp = fh.name
        try:
            out, err, rc = await _run_cmd(
                ["cdncheck", "-l", inp, "-silent", "-json"],
                timeout=timeout, bypass_proxy=True,
            )
        finally:
            try: pathlib.Path(inp).unlink()
            except OSError: pass
        rows = _parse_jsonl(out)
        lines = [f"cdncheck: {len(rows)} classifications"]
        for r in rows[:40]:
            kinds = []
            for k in ("cdn", "waf", "cloud"):
                v = r.get(k)
                if v:
                    kinds.append(f"{k}={v}")
            lines.append(f"  {r.get('host') or r.get('ip','?')}  {' '.join(kinds) or 'none'}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_alterx(roots: list[str], pattern: str = "", timeout: int = 60) -> str:
        """Generate subdomain permutations via alterx.

        Args:
            roots: seed subdomains (e.g. ['api.example.com', 'dev.example.com']).
            pattern: optional alterx pattern DSL ('{{word}}-{{number}}.{{root}}').
            timeout: seconds.
        """
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

    @mcp.tool()
    async def run_chaos(
        domain: str,
        timeout: int = 60,
    ) -> str:
        """PD Chaos subdomain dataset (requires CHAOS_KEY env var).

        Args:
            domain: target apex (e.g. example.com).
            timeout: seconds.
        """
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

    @mcp.tool()
    async def run_dnsgen(
        wordlist_path: str,
        max_outputs: int = 5000,
        timeout: int = 120,
    ) -> str:
        """Permute subdomain wordlist via dnsgen.

        Args:
            wordlist_path: path to seed list (one host per line).
            max_outputs: max permutations returned.
            timeout: seconds.
        """
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

    @mcp.tool()
    async def run_shuffledns(
        wordlist_path: str,
        domain: str = "",
        resolvers_path: str = "",
        mode: str = "bruteforce",
        timeout: int = 600,
    ) -> str:
        """Mass DNS resolve / bruteforce via shuffledns (PD).

        Args:
            wordlist_path: file of subdomains (resolve) or wordlist (bruteforce).
            domain: required for bruteforce mode.
            resolvers_path: path to resolvers list (one IP per line).
            mode: bruteforce | resolve.
            timeout: seconds.
        """
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

    @mcp.tool()
    async def run_graphw00f(target: str, timeout: int = 60) -> str:
        """Fingerprint a GraphQL endpoint engine via graphw00f.

        Args:
            target: GraphQL endpoint URL (e.g. https://example.com/graphql).
            timeout: seconds.
        """
        if not _check_tool("graphw00f"):
            return _not_installed(
                "graphw00f",
                "pip install graphw00f  |  https://github.com/dolevf/graphw00f",
            )
        out, err, rc = await _run_cmd(
            ["graphw00f", "-t", target, "-d", "-f"],
            timeout=timeout, bypass_proxy=True,
        )
        lines = ["graphw00f scan:"]
        clipped = out.strip()
        if not clipped:
            return f"graphw00f: no output [rc={rc}] {err[:200]}"
        lines.extend("  " + ln for ln in clipped.splitlines()[:40])
        return "\n".join(lines)
