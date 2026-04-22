"""Recon pipeline: orchestrates subfinder → katana → nuclei in sequence."""

import os

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_recon_pipeline(
        domain: str,
        depth: str = "quick",
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Run a full recon pipeline: subfinder → katana → nuclei.

        Core tools: subfinder (subdomains), katana (crawl + tech detect), nuclei (vuln scan).
        Gracefully degrades if tools are missing — probe_hosts fills in for katana.

        Args:
            domain: Target domain (e.g. 'example.com')
            depth: 'quick' (subfinder + katana crawl), 'standard' (+ nuclei critical/high), 'deep' (+ nuclei all)
            use_proxy: Route through Burp proxy (default true)
            timeout: Max seconds per tool (default 300)
        """
        domain = _sanitize_domain(domain)
        lines = [f"Recon pipeline for {domain} (depth: {depth})", "=" * 50, ""]
        subdomains = []
        crawled_urls = []

        # Step 1: Subdomain enumeration
        if _check_tool("subfinder"):
            lines.append("[1/3] Running subfinder...")
            cmd = ["subfinder", "-d", domain, "-silent", "-all"]
            stdout, stderr, code = await _run_cmd(cmd, timeout)
            if code == 0 and stdout.strip():
                subdomains = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                lines.append(f"  Found {len(subdomains)} subdomains")
                for sd in subdomains[:20]:
                    lines.append(f"    {sd}")
                if len(subdomains) > 20:
                    lines.append(f"    ... +{len(subdomains) - 20} more")
            else:
                lines.append("  No subdomains found")
        else:
            lines.append("[1/3] subfinder not installed — skipping")
            subdomains = [domain]

        lines.append("")

        # Step 2: Katana crawl (core — does probing + crawling + tech detection)
        target_url = f"https://{domain}"
        if _check_tool("katana"):
            lines.append("[2/3] Running katana (crawl + tech detect)...")
            katana_depth = 2 if depth == "quick" else 3 if depth == "standard" else 5
            cmd = ["katana", "-u", target_url, "-silent", "-no-color",
                   "-d", str(katana_depth), "-jc", "-hh", "-nos", "-fsu", "-xhr",
                   "-td", "-kb", "-e", "cdn,private-ips",
                   "-rl", "100", "-c", "10",
                   "-H", f"User-Agent: {_USER_AGENT}"]
            if use_proxy:
                cmd.extend(["-proxy", BURP_PROXY_URL])

            stdout, stderr, code = await _run_cmd(cmd, timeout)
            if stdout.strip():
                crawled_urls = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                js_count = sum(1 for u in crawled_urls if ".js" in u)
                param_count = sum(1 for u in crawled_urls if "?" in u)
                lines.append(f"  {len(crawled_urls)} URLs ({param_count} parameterized, {js_count} JS)")
                for cu in crawled_urls[:20]:
                    lines.append(f"    {cu}")
                if len(crawled_urls) > 20:
                    lines.append(f"    ... +{len(crawled_urls) - 20} more")
            else:
                lines.append("  Katana returned no results")
        else:
            # Fallback: probe with Burp HTTP client
            lines.append("[2/3] katana not installed — probing with Burp HTTP client...")
            from burpsuite_mcp import client
            data = await client.post("/api/http/curl", json={"url": target_url, "method": "GET"})
            if "error" not in data and data.get("status_code", 0) > 0:
                lines.append(f"  {target_url} [{data.get('status_code')}] ({len(data.get('response_body', ''))} bytes)")
            else:
                lines.append(f"  {target_url} — unreachable")

        lines.append("")

        # Step 3: Nuclei scan
        if depth in ("standard", "deep") and _check_tool("nuclei"):
            templates_dir = os.path.expanduser("~/nuclei-templates")
            if not os.path.isdir(templates_dir) or len(os.listdir(templates_dir)) < 5:
                lines.append("[3/3] Downloading nuclei templates...")
                await _run_cmd(["nuclei", "-ut"], timeout=120)

            lines.append("[3/3] Running nuclei...")
            cmd = ["nuclei", "-u", target_url, "-silent", "-no-color", "-as", "-duc",
                   "-H", f"User-Agent: {_USER_AGENT}",
                   "-rl", "100", "-c", "25", "-bs", "10", "-timeout", "10", "-mhe", "10"]
            if use_proxy:
                # -insecure so Burp's MITM cert doesn't break every HTTPS request
                cmd.extend(["-proxy", BURP_PROXY_URL, "-insecure"])
            if depth == "standard":
                cmd.extend(["-severity", "critical,high"])

            stdout, stderr, code = await _run_cmd(cmd, timeout)
            if stdout.strip():
                findings_raw = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                lines.append(f"  {len(findings_raw)} findings:")
                for fr in findings_raw[:30]:
                    lines.append(f"    {fr}")
                if len(findings_raw) > 30:
                    lines.append(f"    ... +{len(findings_raw) - 30} more")
            else:
                lines.append("  No findings from nuclei")
        elif depth in ("standard", "deep"):
            lines.append("[3/3] nuclei not installed — use auto_probe as alternative")
        else:
            lines.append("[3/3] Skipped (quick mode)")

        lines.append("")
        lines.append("=" * 50)
        lines.append(f"Summary: {len(subdomains)} subdomains, {len(crawled_urls)} URLs crawled")
        if use_proxy:
            lines.append("All traffic routed through Burp proxy — check proxy history.")

        return "\n".join(lines)
