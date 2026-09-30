"""OSINT enumeration — theHarvester (emails, hosts, IPs from passive sources)."""

import re

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain

_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_theharvester(  # cost: expensive (external binary, network-bound)
        domain: str,
        sources: str = "",
        limit: int = 500,
        timeout: int = 300,
    ) -> str:
        """Gather emails, subdomains, hosts and IPs for a domain via theHarvester (passive OSINT).

        Args:
            domain: Target domain
            sources: Comma-separated source list (e.g. 'bing,duckduckgo,crtsh'); empty = 'all'
            limit: Max results to fetch per source (default 500)
            timeout: Max seconds to wait (default 300)
        """
        if not _check_tool("theHarvester"):
            return (
                "Error: theHarvester not installed.\n"
                "  pipx install theHarvester\n"
                "  Or: https://github.com/laramies/theHarvester"
            )

        domain = _sanitize_domain(domain)
        src = sources.strip() or "all"
        # Reject flag/shell injection via the source list (comma-separated tokens only).
        if not re.match(r'^[A-Za-z0-9_,-]+$', src) or src.startswith("-"):
            return f"Error: invalid sources '{sources}' (expected comma-separated source names)"

        cmd = ["theHarvester", "-d", domain, "-b", src, "-l", str(int(limit))]
        stdout, stderr, code = await _run_cmd(cmd, timeout)

        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"theHarvester produced no output for {domain} (exit {code})"

        emails = sorted(set(_EMAIL_RE.findall(out)))
        # Hosts: theHarvester prints 'host.domain' or 'host.domain:ip' lines under
        # "[*] Hosts found". Collect anything ending in the target domain.
        hosts: set[str] = set()
        ips: set[str] = set()
        for raw in out.split("\n"):
            line = raw.strip()
            for ip in _IPV4_RE.findall(line):
                ips.add(ip)
            token = line.split(":")[0].strip().lower()
            if token.endswith(domain) and re.match(r'^[a-z0-9._-]+$', token):
                hosts.add(token)

        lines = [
            f"theHarvester for {domain} (sources: {src})",
            f"  emails: {len(emails)}  hosts: {len(hosts)}  ips: {len(ips)}",
            "",
        ]
        if emails:
            lines.append("Emails:")
            lines.extend(f"  {e}" for e in emails[:100])
            if len(emails) > 100:
                lines.append(f"  ... +{len(emails) - 100} more")
            lines.append("")
        if hosts:
            lines.append("Hosts:")
            lines.extend(f"  {h}" for h in sorted(hosts)[:200])
            if len(hosts) > 200:
                lines.append(f"  ... +{len(hosts) - 200} more")
            lines.append("")
        if ips:
            lines.append("IPs:")
            lines.extend(f"  {i}" for i in sorted(ips)[:100])
        if not (emails or hosts or ips):
            lines.append("No emails, hosts or IPs parsed from output.")
        return "\n".join(lines).rstrip()
