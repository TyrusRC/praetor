"""External recon tool orchestration — optional integration with subfinder, httpx, nuclei, etc.

Security note: All subprocess calls use asyncio.create_subprocess_exec() which passes
arguments as a list (no shell interpretation), preventing command injection. User input
is passed as discrete arguments, never interpolated into shell strings.
"""

import asyncio
import json
import shutil

from mcp.server.fastmcp import FastMCP


def _check_tool(name: str) -> bool:
    """Check if an external tool is installed."""
    return shutil.which(name) is not None


async def _run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a command safely using exec (no shell) and return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
    except asyncio.TimeoutError:
        proc.kill()
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent injection via arguments."""
    # Only allow valid domain characters
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', domain):
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
            "httpx": "Live host probing with tech detection",
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

        lines = ["External Recon Tools:", ""]
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
        if not available:
            lines.append("\nNo external tools found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        return "\n".join(lines)

    @mcp.tool()
    async def run_subfinder(
        domain: str,
        silent: bool = True,
        timeout: int = 120,
    ) -> str:
        """Enumerate subdomains for a target domain using subfinder (passive).

        Requires subfinder to be installed: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

        Args:
            domain: Target domain (e.g. 'example.com')
            silent: Suppress banner output (default: true)
            timeout: Max seconds to wait (default: 120)
        """
        if not _check_tool("subfinder"):
            return "Error: subfinder not installed. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

        domain = _sanitize_domain(domain)
        cmd = ["subfinder", "-d", domain]
        if silent:
            cmd.append("-silent")
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
        tech_detect: bool = True,
        status_code: bool = True,
        timeout: int = 120,
    ) -> str:
        """Probe live hosts from a list of URLs/domains using httpx.

        Requires httpx to be installed: go install github.com/projectdiscovery/httpx/cmd/httpx@latest

        Args:
            targets: List of URLs or domains to probe
            tech_detect: Enable technology detection (default: true)
            status_code: Show status codes (default: true)
            timeout: Max seconds to wait (default: 120)
        """
        if not _check_tool("httpx"):
            return "Error: httpx not installed. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"

        cmd = ["httpx", "-silent", "-no-color"]
        if tech_detect:
            cmd.append("-tech-detect")
        if status_code:
            cmd.append("-status-code")

        input_data = "\n".join(targets)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=input_data.encode()), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            return f"httpx timed out after {timeout}s"

        output = stdout.decode(errors="replace").strip()
        if not output:
            return f"No live hosts found from {len(targets)} targets"

        results = [line.strip() for line in output.split("\n") if line.strip()]
        lines = [f"Live hosts ({len(results)}/{len(targets)}):", ""]
        for r in results[:100]:
            lines.append(f"  {r}")

        if len(results) > 100:
            lines.append(f"  ... and {len(results) - 100} more")

        return "\n".join(lines)

    @mcp.tool()
    async def run_nuclei(
        target: str,
        templates: str = "",
        tags: str = "",
        severity: str = "",
        timeout: int = 300,
    ) -> str:
        """Run nuclei vulnerability scanner against a target.

        Requires nuclei to be installed: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

        Args:
            target: Target URL (e.g. 'https://example.com')
            templates: Specific template directory/file (e.g. 'cves/', 'misconfiguration/')
            tags: Filter by tags (e.g. 'apache,rce', 'cve2024')
            severity: Filter by severity (e.g. 'critical,high')
            timeout: Max seconds to wait (default: 300)
        """
        if not _check_tool("nuclei"):
            return "Error: nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

        cmd = ["nuclei", "-u", target, "-silent", "-no-color", "-jsonl"]
        if templates:
            cmd.extend(["-t", templates])
        if tags:
            cmd.extend(["-tags", tags])
        if severity:
            cmd.extend(["-severity", severity])

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
    async def run_recon_pipeline(
        domain: str,
        depth: str = "quick",
        timeout: int = 300,
    ) -> str:
        """Run a full recon pipeline using available external tools.

        Chains: subfinder → httpx → nuclei (based on available tools).
        Gracefully degrades if tools are missing — works with whatever is installed.

        Args:
            domain: Target domain (e.g. 'example.com')
            depth: 'quick' (subfinder+httpx only), 'standard' (+ nuclei critical/high), 'deep' (+ nuclei all severities)
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

        # Step 2: Live host probing
        targets = subdomains if subdomains else [domain]
        live_hosts = []

        if _check_tool("httpx"):
            lines.append("[2/3] Running httpx...")
            cmd = ["httpx", "-silent", "-status-code", "-no-color"]
            input_data = "\n".join(targets)
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=input_data.encode()), timeout=timeout
                )
                output = stdout.decode(errors="replace").strip()
                if output:
                    live_hosts = [l.strip() for l in output.split("\n") if l.strip()]
                    lines.append(f"  {len(live_hosts)} live hosts:")
                    for lh in live_hosts[:30]:
                        lines.append(f"    {lh}")
                    if len(live_hosts) > 30:
                        lines.append(f"    ... +{len(live_hosts) - 30} more")
                else:
                    lines.append("  No live hosts found")
            except asyncio.TimeoutError:
                proc.kill()
                lines.append("  httpx timed out")
        else:
            lines.append("[2/3] httpx not installed — skipping live host probing")
            live_hosts = [f"https://{domain}"]

        lines.append("")

        # Step 3: Nuclei scan (if depth allows)
        if depth in ("standard", "deep") and _check_tool("nuclei"):
            lines.append("[3/3] Running nuclei...")
            target_url = live_hosts[0].split(" ")[0] if live_hosts else f"https://{domain}"
            if "[" in target_url:
                target_url = target_url.split(" [")[0].strip()

            cmd = ["nuclei", "-u", target_url, "-silent", "-no-color"]
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
