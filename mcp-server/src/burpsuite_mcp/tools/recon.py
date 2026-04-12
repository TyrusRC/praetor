"""External recon tool orchestration — optional integration with subfinder, httpx, nuclei, etc.

Security note: All subprocess calls use asyncio.create_subprocess_exec() which passes
arguments as a list (no shell interpretation), preventing command injection. User input
is passed as discrete arguments, never interpolated into shell strings.
"""

import asyncio
import json
import os
import shutil

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.config import BURP_PROXY_URL

# ProjectDiscovery tools installed via `go install` land in ~/go/bin.
# Prepend it to search path so PD httpx isn't shadowed by Python httpx CLI.
_GO_BIN = os.path.join(os.path.expanduser("~"), "go", "bin")
_SEARCH_PATH = os.pathsep.join([_GO_BIN, os.environ.get("PATH", "")])

# Realistic User-Agent to avoid bot detection on targets
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _find_tool(name: str) -> str | None:
    """Find tool binary, preferring ~/go/bin for ProjectDiscovery tools."""
    return shutil.which(name, path=_SEARCH_PATH)


def _check_tool(name: str) -> bool:
    """Check if an external tool is installed."""
    return _find_tool(name) is not None


async def _run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a command safely using create_subprocess_exec (no shell) and return (stdout, stderr, returncode)."""
    # Resolve full path so ~/go/bin tools aren't shadowed by system packages
    resolved = _find_tool(cmd[0])
    if resolved:
        cmd = [resolved] + cmd[1:]

    # Force Go tools to use C resolver — fixes DNS in WSL2 where Go's pure-Go
    # resolver can't reach DNS servers listed in /etc/resolv.conf
    env = os.environ.copy()
    env["GODEBUG"] = "netdns=cgo"

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent injection via arguments."""
    import re
    # Must start with alphanumeric (reject leading hyphens to prevent flag injection)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


def register(mcp: FastMCP):

    @mcp.tool()
    async def check_recon_tools() -> str:
        """Check which external recon tools are installed on this system.

        Scans PATH for common security tools and reports availability.
        None of these tools are required — they enhance recon when available.
        """
        tools = {
            "subfinder": "Subdomain enumeration (passive)",
            "nuclei": "Template-based vulnerability scanner",
            "katana": "Web crawler / URL discovery",
            "ffuf": "Directory/parameter brute-forcing",
            "nmap": "Port scanning and service detection",
            "dalfox": "XSS scanner",
            "sqlmap": "SQL injection automation",
            "gau": "URL extraction from web archives",
            "waybackurls": "Wayback Machine URL extraction",
            "amass": "Subdomain enumeration (active + passive)",
            "wpscan": "WordPress vulnerability scanner",
        }

        # Check DNS resolution (common WSL issue)
        dns_ok = True
        try:
            import socket
            socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            dns_ok = False

        lines = ["External Recon Tools:", ""]
        if not dns_ok:
            lines.append("WARNING: DNS resolution is broken. Go-based tools (httpx, katana, nuclei)")
            lines.append("will fail. Fix: ensure /etc/resolv.conf has a reachable nameserver.")
            lines.append("For WSL: sudo bash -c 'echo nameserver $(ip route show default | awk \"{print \\$3}\") > /etc/resolv.conf'")
            lines.append("")

        available = []
        missing = []

        for tool, desc in tools.items():
            if _check_tool(tool):
                available.append(f"  [installed] {tool} — {desc}")
            else:
                missing.append(f"  [missing]   {tool} — {desc}")

        if available:
            lines.append(f"Available ({len(available)}):")
            lines.extend(available)
        if missing:
            lines.append(f"\nNot installed ({len(missing)}):")
            lines.extend(missing)

        lines.append(f"\nTotal: {len(available)}/{len(tools)} tools available")
        if missing:
            lines.append("\nInstall commands:")
            lines.append("  # ProjectDiscovery tools")
            lines.append("  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            lines.append("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            lines.append("  CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest")
            lines.append("  # Other Go tools")
            lines.append("  go install -v github.com/hahwul/dalfox/v2@latest")
            lines.append("  go install -v github.com/lc/gau/v2/cmd/gau@latest")
            lines.append("  go install -v github.com/tomnomnom/waybackurls@latest")

        return "\n".join(lines)

    @mcp.tool()
    async def run_subfinder(
        domain: str,
        silent: bool = True,
        use_proxy: bool = True,
        timeout: int = 120,
    ) -> str:
        """Enumerate subdomains for a target domain using subfinder (passive).

        Requires subfinder to be installed: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

        Args:
            domain: Target domain (e.g. 'example.com')
            silent: Suppress banner output (default: true)
            use_proxy: Route requests through Burp proxy so they appear in proxy history (default: true)
            timeout: Max seconds to wait (default: 120)
        """
        if not _check_tool("subfinder"):
            return "Error: subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

        domain = _sanitize_domain(domain)
        cmd = ["subfinder", "-d", domain, "-all"]
        if silent:
            cmd.append("-silent")
        if use_proxy:
            cmd.extend(["-proxy", BURP_PROXY_URL])
        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0:
            return f"subfinder failed (exit {code}): {stderr[:500]}"

        subdomains = [line.strip() for line in stdout.strip().split("\n") if line.strip()]

        if not subdomains:
            return f"No subdomains found for {domain}"

        lines = [f"Subdomains for {domain} ({len(subdomains)}):", ""]
        for sd in subdomains[:200]:
            lines.append(f"  {sd}")

        if len(subdomains) > 200:
            lines.append(f"  ... and {len(subdomains) - 200} more")

        return "\n".join(lines)

    @mcp.tool()
    async def run_httpx(
        targets: list[str],
        timeout: int = 30,
    ) -> str:
        """Probe live hosts from a list of URLs/domains. Returns status code and response size.
        Uses curl (always available) instead of ProjectDiscovery httpx for reliability.

        Args:
            targets: List of URLs or domains to probe
            timeout: Max seconds per target (default: 30)
        """
        from burpsuite_mcp import client

        results = []
        for target in targets:
            url = target if "://" in target else f"https://{target}"
            data = await client.post("/api/http/curl", json={
                "url": url, "method": "GET",
            })
            if "error" not in data:
                status = data.get("status_code", 0)
                length = len(data.get("response_body", ""))
                headers = data.get("response_headers", [])
                server = next((h["value"] for h in headers if h["name"].lower() == "server"), "")
                tech = next((h["value"] for h in headers if h["name"].lower() == "x-powered-by"), "")
                info = f"[{status}]"
                if server:
                    info += f" [{server}]"
                if tech:
                    info += f" [{tech}]"
                results.append(f"  {url} {info} ({length} bytes)")
            else:
                results.append(f"  {url} [FAILED] {data['error'][:100]}")

        if not results:
            return "No targets provided"

        lines = [f"Live hosts ({len(results)}/{len(targets)}):", ""]
        lines.extend(results)
        return "\n".join(lines)

    @mcp.tool()
    async def run_nuclei(
        target: str,
        templates: str = "",
        tags: str = "",
        severity: str = "",
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run nuclei vulnerability scanner against a target.

        Requires nuclei to be installed: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

        Args:
            target: Target URL (e.g. 'https://example.com')
            templates: Specific template directory/file (e.g. 'cves/', 'misconfiguration/')
            tags: Filter by tags (e.g. 'apache,rce', 'cve2024')
            severity: Filter by severity (e.g. 'critical,high')
            use_proxy: Route requests through Burp proxy so they appear in proxy history (default: true)
            timeout: Max seconds to wait (default: 300)
        """
        if not _check_tool("nuclei"):
            return "Error: nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

        # Auto-download templates if missing (first run)
        templates_dir = os.path.expanduser("~/nuclei-templates")
        if not os.path.isdir(templates_dir) or len(os.listdir(templates_dir)) < 5:
            await _run_cmd(["nuclei", "-ut"], timeout=120)

        cmd = ["nuclei", "-u", target, "-silent", "-no-color", "-jsonl",
               "-H", f"User-Agent: {_USER_AGENT}",
               "-rl", "50", "-c", "10"]  # rate limit 50 req/s, 10 concurrent
        if templates:
            cmd.extend(["-t", templates])
        if tags:
            cmd.extend(["-tags", tags])
        if severity:
            cmd.extend(["-severity", severity])
        if use_proxy:
            cmd.extend(["-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"nuclei failed (exit {code}): {stderr[:500]}"

        findings = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "template": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", ""),
                    "matched": finding.get("matched-at", ""),
                    "type": finding.get("type", ""),
                })
            except json.JSONDecodeError:
                if line:
                    findings.append({"raw": line})

        if not findings:
            return f"No findings from nuclei scan of {target}"

        lines = [f"Nuclei findings for {target} ({len(findings)}):", ""]
        for f in findings[:50]:
            if "raw" in f:
                lines.append(f"  {f['raw']}")
            else:
                sev = f.get("severity", "?").upper()
                lines.append(f"  [{sev}] {f.get('name', f.get('template', '?'))}")
                if f.get("matched"):
                    lines.append(f"       → {f['matched']}")

        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")

        return "\n".join(lines)

    @mcp.tool()
    async def run_katana(
        target: str,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
        known_files: bool = False,
        form_fill: bool = False,
        scope_domain: str = "",
        use_proxy: bool = True,
        timeout: int = 180,
    ) -> str:
        """Crawl a target with katana to discover URLs, endpoints, and JavaScript-rendered paths.

        katana is ProjectDiscovery's next-gen web crawler — faster than traditional crawlers
        and capable of parsing JavaScript to find hidden API endpoints and routes.

        Requires katana: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

        Args:
            target: Target URL (e.g. 'https://example.com')
            depth: Crawl depth (default 3, max 10)
            js_crawl: Enable JavaScript parsing/crawling to discover API endpoints in JS code (default true)
            headless: Use headless browser for JavaScript-rendered pages (default false — slower but finds more)
            known_files: Probe for known files like robots.txt, sitemap.xml (default false)
            form_fill: Automatically fill and submit forms during crawl (default false)
            scope_domain: Restrict crawl to this domain (default: auto from target URL)
            use_proxy: Route requests through Burp proxy (default true)
            timeout: Max seconds to wait (default 180)
        """
        if not _check_tool("katana"):
            return "Error: katana not installed. Install: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest"

        depth = min(depth, 10)
        cmd = ["katana", "-u", target, "-silent", "-no-color", "-d", str(depth),
               "-H", f"User-Agent: {_USER_AGENT}"]

        if js_crawl:
            cmd.append("-jc")
        if headless:
            cmd.extend(["-headless", "-no-sandbox"])
        if known_files:
            cmd.extend(["-kf", "all"])
        if form_fill:
            cmd.append("-aff")
        if scope_domain:
            cmd.extend(["-fs", _sanitize_domain(scope_domain)])
        if use_proxy:
            cmd.extend(["-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"katana failed (exit {code}): {stderr[:500]}"

        urls = [line.strip() for line in stdout.strip().split("\n") if line.strip()]

        if not urls:
            return f"No URLs discovered by katana for {target}"

        # Categorize URLs
        js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u or "/graphql" in u]
        form_urls = [u for u in urls if "?" in u]
        other_urls = [u for u in urls if u not in js_urls and u not in api_urls and u not in form_urls]

        lines = [f"Katana crawl of {target} ({len(urls)} URLs, depth={depth}):", ""]

        if api_urls:
            lines.append(f"  API endpoints ({len(api_urls)}):")
            for u in api_urls[:20]:
                lines.append(f"    {u}")
            if len(api_urls) > 20:
                lines.append(f"    ... +{len(api_urls) - 20} more")

        if form_urls:
            lines.append(f"\n  Parameterized URLs ({len(form_urls)}):")
            for u in form_urls[:20]:
                lines.append(f"    {u}")
            if len(form_urls) > 20:
                lines.append(f"    ... +{len(form_urls) - 20} more")

        if js_urls:
            lines.append(f"\n  JavaScript files ({len(js_urls)}):")
            for u in js_urls[:15]:
                lines.append(f"    {u}")
            if len(js_urls) > 15:
                lines.append(f"    ... +{len(js_urls) - 15} more")

        if other_urls:
            lines.append(f"\n  Other pages ({len(other_urls)}):")
            for u in other_urls[:20]:
                lines.append(f"    {u}")
            if len(other_urls) > 20:
                lines.append(f"    ... +{len(other_urls) - 20} more")

        lines.append(f"\nTotal: {len(urls)} URLs ({len(api_urls)} API, {len(form_urls)} parameterized, {len(js_urls)} JS)")
        if use_proxy:
            lines.append("All requests went through Burp proxy — check proxy history.")

        return "\n".join(lines)

    @mcp.tool()
    async def run_recon_pipeline(
        domain: str,
        depth: str = "quick",
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Run a full recon pipeline using available external tools.

        Chains: subfinder → httpx → nuclei (based on available tools).
        Gracefully degrades if tools are missing — works with whatever is installed.
        All HTTP requests are routed through Burp's proxy by default.

        Args:
            domain: Target domain (e.g. 'example.com')
            depth: 'quick' (subfinder+httpx only), 'standard' (+ nuclei critical/high), 'deep' (+ nuclei all severities)
            use_proxy: Route requests through Burp proxy (default: true)
            timeout: Max seconds per tool (default: 300)
        """
        domain = _sanitize_domain(domain)
        lines = [f"Recon pipeline for {domain} (depth: {depth})", "=" * 50, ""]
        subdomains = []

        # Step 1: Subdomain enumeration
        if _check_tool("subfinder"):
            lines.append("[1/3] Running subfinder...")
            cmd = ["subfinder", "-d", domain, "-silent"]
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
            lines.append("[1/3] subfinder not installed — skipping subdomain enumeration")
            subdomains = [domain]

        lines.append("")

        # Step 2: Live host probing (via Burp HTTP client — no external tool needed)
        targets = subdomains if subdomains else [domain]
        live_hosts = []

        lines.append("[2/3] Probing live hosts...")
        from burpsuite_mcp import client
        for t in targets[:50]:  # limit to 50 targets
            url = t if "://" in t else f"https://{t}"
            data = await client.post("/api/http/curl", json={"url": url, "method": "GET"})
            if "error" not in data and data.get("status_code", 0) > 0:
                status = data.get("status_code", 0)
                live_hosts.append(f"{url} [{status}]")
        if live_hosts:
            lines.append(f"  {len(live_hosts)} live hosts:")
            for lh in live_hosts[:30]:
                lines.append(f"    {lh}")
            if len(live_hosts) > 30:
                lines.append(f"    ... +{len(live_hosts) - 30} more")
        else:
            lines.append("  No live hosts found")
            live_hosts = [f"https://{domain}"]

        lines.append("")

        # Step 2.5: Katana crawl for URL discovery
        if _check_tool("katana") and depth in ("standard", "deep"):
            lines.append("[2.5/3] Running katana...")
            target_url = live_hosts[0].split(" ")[0] if live_hosts else f"https://{domain}"
            if "[" in target_url:
                target_url = target_url.split(" [")[0].strip()

            katana_depth = 2 if depth == "standard" else 4
            cmd = ["katana", "-u", target_url, "-silent", "-no-color", "-d", str(katana_depth), "-jc",
                   "-H", f"User-Agent: {_USER_AGENT}"]
            if use_proxy:
                cmd.extend(["-proxy", BURP_PROXY_URL])

            stdout, stderr, code = await _run_cmd(cmd, timeout)
            if stdout.strip():
                crawled_urls = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                lines.append(f"  {len(crawled_urls)} URLs discovered:")
                for cu in crawled_urls[:20]:
                    lines.append(f"    {cu}")
                if len(crawled_urls) > 20:
                    lines.append(f"    ... +{len(crawled_urls) - 20} more")
            else:
                lines.append("  No URLs discovered")
            lines.append("")

        # Step 3: Nuclei scan (if depth allows)
        if depth in ("standard", "deep") and _check_tool("nuclei"):
            # Auto-download templates if missing
            templates_dir = os.path.expanduser("~/nuclei-templates")
            if not os.path.isdir(templates_dir) or len(os.listdir(templates_dir)) < 5:
                lines.append("[3/3] Downloading nuclei templates...")
                await _run_cmd(["nuclei", "-ut"], timeout=120)

            lines.append("[3/3] Running nuclei...")
            target_url = live_hosts[0].split(" ")[0] if live_hosts else f"https://{domain}"
            if "[" in target_url:
                target_url = target_url.split(" [")[0].strip()

            cmd = ["nuclei", "-u", target_url, "-silent", "-no-color",
                   "-H", f"User-Agent: {_USER_AGENT}", "-rl", "50", "-c", "10"]
            if use_proxy:
                cmd.extend(["-proxy", BURP_PROXY_URL])
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
            lines.append("[3/3] nuclei not installed — skipping vulnerability scan")
        else:
            lines.append("[3/3] Skipped (quick mode)")

        lines.append("")
        lines.append("=" * 50)
        lines.append(f"Summary: {len(subdomains)} subdomains, {len(live_hosts)} live hosts")
        lines.append("Use Burp Suite tools for deeper analysis on discovered hosts.")

        return "\n".join(lines)
