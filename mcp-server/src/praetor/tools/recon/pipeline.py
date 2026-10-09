"""Recon pipeline: orchestrates subfinder → katana → nuclei in sequence."""

import json

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_recon_pipeline(
        domain: str,
        depth: str = "quick",
        max_hosts: int = 10,
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Run a full recon pipeline: subfinder, probe, katana, nuclei. Degrades gracefully if tools missing.

        Args:
            domain: Target domain
            depth: 'quick', 'standard' (+ nuclei crit/high), or 'deep' (+ nuclei all)
            max_hosts: Cap on live hosts to crawl/scan (default 10)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds per tool invocation (default 300)
        """
        domain = _sanitize_domain(domain)
        from praetor.tools.intel.cost_cap import budget_gate
        _over = budget_gate(domain)
        if _over:
            return _over
        lines = [f"Recon pipeline for {domain} (depth: {depth})", "=" * 50, ""]
        subdomains: list[str] = []
        live_hosts: list[str] = []
        crawled_urls: list[str] = []
        all_traffic_proxied = use_proxy  # downgraded to False if any step bypasses Burp

        # Step 1: Subdomain enumeration
        if _check_tool("subfinder"):
            lines.append("[1/4] Running subfinder...")
            max_time_minutes = max(1, timeout // 60)
            cmd = ["subfinder", "-d", domain, "-silent",
                   "-max-time", str(max_time_minutes),
                   "-timeout", "15"]
            if use_proxy:
                cmd.extend(["-proxy", BURP_PROXY_URL])
            stdout, stderr, code = await _run_cmd(cmd, timeout)
            if code == 0 and stdout.strip():
                subdomains = sorted({l.strip() for l in stdout.strip().split("\n") if l.strip()})
                lines.append(f"  Found {len(subdomains)} subdomains")
                for sd in subdomains[:20]:
                    lines.append(f"    {sd}")
                if len(subdomains) > 20:
                    lines.append(f"    ... +{len(subdomains) - 20} more")
            else:
                lines.append("  No subdomains found — falling back to root domain")
                subdomains = [domain]
        else:
            lines.append("[1/4] subfinder not installed — using root domain only")
            subdomains = [domain]

        lines.append("")

        # Step 2: Probe which subdomains are live via Burp HTTP client
        probe_targets = subdomains[: max_hosts * 3]  # probe up to 3x what we'll crawl
        lines.append(f"[2/4] Probing {len(probe_targets)} hosts for liveness...")
        from praetor import client
        for sd in probe_targets:
            url = sd if "://" in sd else f"https://{sd}"
            probe = await client.post("/api/http/curl", json={"url": url, "method": "GET"})
            if "error" not in probe and probe.get("status_code", 0) > 0:
                live_hosts.append(url)
        live_hosts = live_hosts[:max_hosts]
        lines.append(f"  {len(live_hosts)} live hosts (capped at {max_hosts}):")
        for lh in live_hosts[:10]:
            lines.append(f"    {lh}")
        if len(live_hosts) > 10:
            lines.append(f"    ... +{len(live_hosts) - 10} more")
        if not live_hosts:
            lines.append("  No live hosts — aborting crawl/scan steps")
            return "\n".join(lines)

        lines.append("")

        # Step 3: Katana crawl per live host
        if _check_tool("katana"):
            lines.append(f"[3/4] Running katana against {len(live_hosts)} hosts...")
            katana_depth = 2 if depth == "quick" else 3 if depth == "standard" else 5
            per_host_timeout = max(30, timeout // max(1, len(live_hosts)))
            for host_url in live_hosts:
                cmd = ["katana", "-u", host_url, "-silent", "-no-color",
                       "-d", str(katana_depth), "-jc", "-hh", "-nos", "-fsu", "-xhr",
                       "-td", "-kb", "-e", "cdn,private-ips",
                       "-rl", "100", "-c", "10",
                       "-H", f"User-Agent: {_USER_AGENT}"]
                if use_proxy:
                    cmd.extend(["-proxy", BURP_PROXY_URL])
                stdout, _, _ = await _run_cmd(cmd, per_host_timeout)
                if stdout.strip():
                    host_urls = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                    crawled_urls.extend(host_urls)
            js_count = sum(1 for u in crawled_urls if ".js" in u)
            param_count = sum(1 for u in crawled_urls if "?" in u)
            lines.append(f"  {len(crawled_urls)} total URLs ({param_count} parameterized, {js_count} JS)")
            for cu in crawled_urls[:20]:
                lines.append(f"    {cu}")
            if len(crawled_urls) > 20:
                lines.append(f"    ... +{len(crawled_urls) - 20} more")
        else:
            lines.append("[3/4] katana not installed — skipping crawl (use browser_crawl as alternative)")

        lines.append("")

        # Step 4: deep scan per live host with assay (the web-scan engine).
        if depth in ("standard", "deep") and _check_tool("assay"):
            profile = "thorough" if depth == "deep" else "quick"
            # Share the step's time budget across hosts so the whole step stays
            # within `timeout`.
            per_host = max(60, timeout // max(1, len(live_hosts)))
            lines.append(
                f"[4/4] Running assay ({profile}) against {len(live_hosts)} hosts...")
            total = 0
            for host_url in live_hosts:
                cmd = ["assay", "scan", host_url, "--json",
                       "--profile", profile, "--timeout", f"{per_host}s"]
                if use_proxy:
                    cmd.extend(["--proxy", BURP_PROXY_URL, "-k"])
                stdout, _stderr, _code = await _run_cmd(
                    cmd, per_host + 30, bypass_proxy=not use_proxy)
                fs = []
                if stdout.strip():
                    try:
                        fs = (json.loads(stdout).get("scan_result") or {}).get("findings") or []
                    except ValueError:
                        fs = []
                for fdg in fs[:20]:
                    sev = str(fdg.get("severity", "?")).upper()
                    name = fdg.get("title") or fdg.get("type") or "?"
                    lines.append(f"    [{sev}] {name} → {fdg.get('url', '')}")
                total += len(fs)
            lines.append(f"  {total} findings across {len(live_hosts)} hosts")
        elif depth in ("standard", "deep"):
            lines.append("[4/4] assay not installed — use auto_probe as alternative "
                         "(build: go build -o ~/go/bin/assay ./cmd/assay)")
        else:
            lines.append("[4/4] Skipped (quick mode)")

        lines.append("")
        lines.append("=" * 50)
        lines.append(
            f"Summary: {len(subdomains)} subdomains, {len(live_hosts)} live, "
            f"{len(crawled_urls)} URLs crawled"
        )
        if all_traffic_proxied:
            lines.append("All external-tool traffic routed through Burp proxy — check proxy history.")

        return "\n".join(lines)
