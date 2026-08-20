"""analyze_dns — full DNS record dump with security analysis."""

import socket

from mcp.server.fastmcp import FastMCP

from ._common import _sanitize_domain, _dig, _dig_available


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def analyze_dns(domain: str) -> str:
        """Analyze DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) and flag security-relevant findings.

        Args:
            domain: Target domain
        """
        domain = _sanitize_domain(domain)
        lines = [f"DNS records for {domain}:", ""]
        notes: list[str] = []

        dig_ok = _dig_available()
        if not dig_ok:
            lines.append("  [!] `dig` not found on PATH — only A/AAAA records available")
            lines.append("      Install BIND utils (Linux: `apt install dnsutils`;")
            lines.append("      Windows: `scoop install dnsutils` or use WSL)")
            lines.append("")

        try:
            a_records: set[str] = set()
            results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            for _, _, _, _, addr in results:
                a_records.add(addr[0])
            if a_records:
                lines.append("  A records:")
                for ip in sorted(a_records):
                    lines.append(f"    {ip}")
        except socket.gaierror:
            lines.append("  A records: NXDOMAIN / resolution failed")
            notes.append("Domain does not resolve — possible expired or parked domain")

        try:
            aaaa_records: set[str] = set()
            results = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            for _, _, _, _, addr in results:
                aaaa_records.add(addr[0])
            if aaaa_records:
                lines.append("  AAAA records:")
                for ip in sorted(aaaa_records):
                    lines.append(f"    {ip}")
        except socket.gaierror:
            pass

        for rtype in ["CNAME", "MX", "NS", "TXT", "SOA"]:
            result = await _dig(domain, rtype)
            if result:
                lines.append(f"  {rtype} records:")
                for record_line in result.split("\n"):
                    record_line = record_line.strip()
                    if not record_line:
                        continue
                    lines.append(f"    {record_line}")

                    if rtype == "TXT":
                        if "v=spf1" in record_line:
                            notes.append(f"SPF record found: {record_line[:100]}")
                        if "v=DMARC1" in record_line.upper():
                            notes.append(f"DMARC record found: {record_line[:100]}")
                    if rtype == "CNAME":
                        if not record_line.rstrip(".").endswith(domain):
                            notes.append(f"External CNAME: {domain} -> {record_line} (check for takeover)")
                    if rtype == "MX":
                        if "google" in record_line.lower():
                            notes.append("Mail hosted on Google Workspace")
                        elif "outlook" in record_line.lower() or "microsoft" in record_line.lower():
                            notes.append("Mail hosted on Microsoft 365")

        dmarc_result = await _dig(f"_dmarc.{domain}", "TXT")
        if dmarc_result:
            lines.append(f"  DMARC (_dmarc.{domain}):")
            for record_line in dmarc_result.split("\n"):
                if record_line.strip():
                    lines.append(f"    {record_line.strip()}")
                    notes.append(f"DMARC policy: {record_line.strip()[:100]}")
        else:
            notes.append("No DMARC record found")

        wildcard_result = await _dig(f"random-nonexistent-sub-1337.{domain}", "A")
        if wildcard_result:
            notes.append(f"Wildcard DNS detected (*.{domain} -> {wildcard_result})")

        if notes:
            lines.append("")
            lines.append("  Security notes:")
            for note in notes:
                lines.append(f"    - {note}")

        return "\n".join(lines)
