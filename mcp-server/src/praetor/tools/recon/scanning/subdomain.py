"""Subdomain enumeration: amass."""

from mcp.server.fastmcp import FastMCP

from .._common import _check_tool, _run_cmd


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_amass(
        domain: str,
        mode: str = "enum",
        passive: bool = True,
        timeout: int = 900,
    ) -> str:
        """Deep subdomain enumeration via Amass. Requires amass installed.

        Complements subfinder: subfinder is fast and passive, Amass is slower
        but more thorough (53+ data sources passive, brute + zone-walk active).
        Use Amass when subfinder's surface is too thin.

        Direct connect — bypasses Burp proxy because Amass queries passive
        subdomain databases (CT logs, WHOIS, DNS) that don't need archiving.

        Args:
            domain: Target apex domain (example.com)
            mode: enum (subdomain discovery) | intel (org/IP intelligence)
            passive: True = sources-only (quiet). False = active probing too.
            timeout: Max seconds (default 900 — Amass is slow)
        """
        if not _check_tool("amass"):
            return (
                "Error: amass not installed.\n"
                "  go install -v github.com/owasp-amass/amass/v4/...@master  OR\n"
                "  snap install amass  OR  brew install amass"
            )
        from .._common import _sanitize_domain
        try:
            domain = _sanitize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"
        cmd = ["amass", mode, "-d", domain, "-nocolor"]
        if passive:
            cmd.append("-passive")
        stdout, stderr, code = await _run_cmd(cmd, timeout, bypass_proxy=True)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"amass produced no output (exit {code})"
        # Subdomain lines look like `example.com (FQDN) --> a_record --> 1.2.3.4`
        hosts = set()
        for line in out.split("\n"):
            stripped = line.strip()
            if domain in stripped:
                # Try to pull the FQDN at start of line
                first = stripped.split()[0].rstrip(",")
                if first.endswith(domain) or first == domain:
                    hosts.add(first)
        lines = [f"amass {mode} for {domain} ({len(hosts)} hosts):", ""]
        for h in sorted(hosts)[:200]:
            lines.append(f"  {h}")
        if len(hosts) > 200:
            lines.append(f"  ... +{len(hosts) - 200} more")
        return "\n".join(lines)
