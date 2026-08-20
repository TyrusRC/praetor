"""fetch_wayback_urls — Wayback Machine CDX URL harvest."""

import httpx
from mcp.server.fastmcp import FastMCP

from ._common import _sanitize_domain


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def fetch_wayback_urls(
        domain: str,
        limit: int = 30,
        filter_status: str = "200",
    ) -> str:
        """Get historical URLs from the Wayback Machine CDX API.

        Args:
            domain: Target domain
            limit: Max URLs to return (default 30 — pass higher explicitly when you need full archive)
            filter_status: HTTP status filter (default '200', '' for all)
        """
        domain = _sanitize_domain(domain)
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,statuscode,timestamp",
            "collapse": "urlkey",
            "limit": str(limit),
        }
        if filter_status:
            params["filter"] = f"statuscode:{filter_status}"

        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params=params,
                )
                resp.raise_for_status()
                rows = resp.json()
        except httpx.TimeoutException:
            return "Error: Wayback Machine timed out (30s). Try again later."
        except httpx.HTTPStatusError as e:
            return f"Error: Wayback Machine returned HTTP {e.response.status_code}"
        except Exception as e:
            return f"Error querying Wayback Machine: {e}"

        if not isinstance(rows, list):
            return f"Error: Wayback Machine returned unexpected payload: {str(rows)[:200]}"
        if not rows or len(rows) <= 1:
            return f"No Wayback URLs found for {domain}"

        data_rows = rows[1:]

        seen: set[str] = set()
        urls: list[str] = []
        for row in data_rows:
            url_val = row[0] if len(row) > 0 else ""
            if url_val and url_val not in seen:
                seen.add(url_val)
                urls.append(url_val)

        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u or "/v3/" in u or "/graphql" in u]
        js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        interesting = [u for u in urls if any(p in u.lower() for p in [
            ".env", ".git", ".bak", ".old", ".sql", ".zip", ".tar",
            "config", "admin", "debug", "backup", ".log", "phpinfo",
            ".swp", ".DS_Store", "wp-config", ".htaccess",
        ])]
        pages = [u for u in urls if u not in set(api_urls + js_urls + interesting)]

        lines = [f"Wayback URLs for {domain} ({len(urls)} unique):", ""]

        if interesting:
            lines.append(f"  Interesting files ({len(interesting)}):")
            for u in interesting[:30]:
                lines.append(f"    {u}")
            if len(interesting) > 30:
                lines.append(f"    ... +{len(interesting) - 30} more")
            lines.append("")

        if api_urls:
            lines.append(f"  API endpoints ({len(api_urls)}):")
            for u in api_urls[:30]:
                lines.append(f"    {u}")
            if len(api_urls) > 30:
                lines.append(f"    ... +{len(api_urls) - 30} more")
            lines.append("")

        if js_urls:
            lines.append(f"  JavaScript files ({len(js_urls)}):")
            for u in js_urls[:20]:
                lines.append(f"    {u}")
            if len(js_urls) > 20:
                lines.append(f"    ... +{len(js_urls) - 20} more")
            lines.append("")

        if pages:
            lines.append(f"  Pages ({len(pages)}):")
            for u in pages[:30]:
                lines.append(f"    {u}")
            if len(pages) > 30:
                lines.append(f"    ... +{len(pages) - 30} more")

        lines.append(f"\nTotal: {len(urls)} URLs ({len(api_urls)} API, {len(js_urls)} JS, {len(interesting)} interesting, {len(pages)} pages)")
        return "\n".join(lines)
