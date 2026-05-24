"""NVD-API search bridge — search_cve."""

from mcp.server.fastmcp import FastMCP

from .nvd import _nvd_lookup


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def search_cve(
        query: str,
        tech: str = "",
        live_lookup: bool = True,
        max_results: int = 10,
    ) -> str:
        """Search CVEs via live NVD 2.0 API lookup or offline search URLs.

        Args:
            query: Search query (CVE ID, product name, or keyword)
            tech: Optional technology context for targeted search
            live_lookup: Query NVD API live (default True); False for URLs only
            max_results: Max NVD results (default 10, max 50)
        """
        import urllib.parse
        q = urllib.parse.quote_plus(query)

        lines = [f"CVE Search for: {query}"]
        if tech:
            lines.append(f"Technology: {tech}")
        lines.append("")

        if live_lookup:
            structured = await _nvd_lookup(query, min(max(1, max_results), 50))
            if isinstance(structured, str):
                lines.append(f"NVD lookup failed: {structured}")
            else:
                lines.append(f"NVD results ({len(structured)}):")
                for c in structured:
                    cvss = c.get("cvss_score")
                    cvss_str = f" [CVSS {cvss}]" if cvss is not None else ""
                    lines.append(f"  {c['id']}{cvss_str} ({c.get('published', '?')[:10]})")
                    summary = c.get("summary", "").replace("\n", " ")[:220]
                    if summary:
                        lines.append(f"    {summary}")
                lines.append("")

        lines.append("Search URLs:")
        lines.append(f"  NVD: https://nvd.nist.gov/vuln/search/results?query={q}")
        lines.append(f"  Exploit-DB: https://www.exploit-db.com/search?q={q}")
        lines.append(f"  GitHub Advisory: https://github.com/advisories?query={q}")

        if query.upper().startswith("CVE-"):
            lines.append(f"  MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={query}")
            lines.append(f"  NVD Detail: https://nvd.nist.gov/vuln/detail/{query}")

        if tech:
            tag = tech.lower().split("/")[0].split(" ")[0]
            lines.append(f"  nuclei: run_nuclei(target=TARGET, tags='{tag}')")

        return "\n".join(lines)
