"""Subdomain enumeration tools."""

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_subfinder(
        domain: str,
        all_sources: bool = False,
        silent: bool = True,
        use_proxy: bool = True,
        timeout: int = 120,
    ) -> str:
        """Enumerate subdomains for a target domain using subfinder (passive).

        Requires subfinder to be installed: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

        Args:
            domain: Target domain (e.g. 'example.com')
            all_sources: Query every configured passive source (-all). Much slower;
                         many sources require API keys and time out otherwise. Default False
                         uses subfinder's built-in set of free/reliable sources.
            silent: Suppress banner output (default: true)
            use_proxy: Route subfinder's passive-source API calls through Burp proxy
                       so they appear in proxy history (default: true)
            timeout: Max seconds to wait (default: 120)
        """
        if not _check_tool("subfinder"):
            return "Error: subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

        domain = _sanitize_domain(domain)
        # -max-time is in minutes; cap at timeout-10s so we give our _run_cmd kill a buffer
        max_time_minutes = max(1, (timeout - 10) // 60) if timeout > 70 else 1
        cmd = ["subfinder", "-d", domain,
               "-max-time", str(max_time_minutes),
               "-timeout", "15"]                # per-source timeout
        if all_sources:
            cmd.append("-all")
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
