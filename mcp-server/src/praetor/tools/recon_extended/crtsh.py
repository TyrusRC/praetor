"""query_crtsh — Certificate Transparency log subdomain enum."""

import httpx
from mcp.server.fastmcp import FastMCP

from ._common import _sanitize_domain


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def query_crtsh(domain: str, include_expired: bool = False) -> str:
        """Query crt.sh Certificate Transparency logs for subdomains.

        Args:
            domain: Target domain
            include_expired: Include expired certificates (default false)
        """
        domain = _sanitize_domain(domain)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        if not include_expired:
            url += "&exclude=expired"

        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.get(url)
                resp.raise_for_status()
                entries = resp.json()
        except httpx.TimeoutException:
            return "Error: crt.sh timed out (30s). The service can be slow — try again later."
        except httpx.HTTPStatusError as e:
            return f"Error: crt.sh returned HTTP {e.response.status_code}"
        except Exception as e:
            return f"Error querying crt.sh: {e}"

        if not entries:
            return f"No CT log entries found for {domain}"

        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name.endswith(domain) and "*" not in name:
                    subdomains.add(name)

        sorted_subs = sorted(subdomains)

        lines = [f"CT subdomains for {domain} ({len(sorted_subs)} unique):", ""]
        for sub in sorted_subs[:300]:
            lines.append(f"  {sub}")
        if len(sorted_subs) > 300:
            lines.append(f"  ... +{len(sorted_subs) - 300} more")

        lines.append(f"\nTotal: {len(sorted_subs)} subdomains from {len(entries)} CT log entries")
        return "\n".join(lines)
