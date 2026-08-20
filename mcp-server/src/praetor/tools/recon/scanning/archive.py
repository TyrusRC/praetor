"""URL archive aggregation: gau."""

from mcp.server.fastmcp import FastMCP

from .._common import _check_tool, _run_cmd


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_gau(
        domain: str,
        providers: str = "wayback,otx,urlscan,commoncrawl",
        subdomains: bool = True,
        timeout: int = 300,
    ) -> str:
        """Aggregate URLs across Wayback Machine, AlienVault OTX, URLScan, Common Crawl.

        Broader than our `fetch_wayback_urls` (single-source). Useful for
        finding archived endpoints / parameters that no longer appear in the
        live app. Direct connect — providers are public archives, no point
        proxying through Burp.

        Args:
            domain: Target apex domain (example.com)
            providers: Comma-separated: wayback / otx / urlscan / commoncrawl
            subdomains: True to include subdomain URLs in aggregation
            timeout: Max seconds (default 300)
        """
        if not _check_tool("gau"):
            return (
                "Error: gau not installed.\n"
                "  go install github.com/lc/gau/v2/cmd/gau@latest"
            )
        from .._common import _sanitize_domain
        try:
            domain = _sanitize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"
        cmd = ["gau", domain, "--providers", providers, "--threads", "10"]
        if subdomains:
            cmd.append("--subs")
        stdout, stderr, code = await _run_cmd(cmd, timeout, bypass_proxy=True)
        out = stdout.strip()
        if not out:
            return f"gau produced no output (exit {code}). Verify providers and connectivity."
        urls = [u for u in out.split("\n") if u.strip()]
        # Dedupe and sort for readability
        urls = sorted(set(urls))
        lines = [f"gau for {domain} ({len(urls)} unique URLs):", ""]
        for u in urls[:400]:
            lines.append(f"  {u}")
        if len(urls) > 400:
            lines.append(f"  ... +{len(urls) - 400} more")
        lines.append("")
        lines.append("Next: feed into smart_analyze / extract_links / auto_probe for testing.")
        return "\n".join(lines)
