"""Tools for controlling Burp Suite scanner - trigger scans, crawls, check status."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def scan_url(
        url: str = "",
        urls: list[str] | None = None,
        index: int = -1,
    ) -> str:
        """Start an active scan/audit on a target through Burp Suite Professional.
        Scans the target for vulnerabilities (SQLi, XSS, SSRF, etc.).

        Provide ONE of:
        - url: Single URL to scan (e.g. 'https://target.com/api/users?id=1')
        - urls: List of URLs to scan
        - index: Proxy history index to scan a captured request

        The scan runs in the background. Use get_scan_status() to check progress
        and get_scanner_findings() to see results.

        Args:
            url: Single target URL to scan
            urls: Multiple target URLs to scan
            index: Proxy history index of request to scan
        """
        payload: dict = {}
        if index >= 0:
            payload["index"] = index
        elif urls:
            payload["urls"] = urls
        elif url:
            payload["url"] = url
        else:
            return "Error: Provide 'url', 'urls', or 'index'"

        data = await client.post("/api/scanner/scan", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [
            f"Scan started (ID: {data.get('scan_id')})",
            f"  {data.get('message', '')}",
            "",
            "Use get_scan_status() to check progress and get_scanner_findings() for results.",
        ]
        return "\n".join(lines)

    @mcp.tool()
    async def crawl_target(
        url: str = "",
        urls: list[str] | None = None,
    ) -> str:
        """Start a crawl on target URLs to discover endpoints and content.
        Burp will spider the target, discovering pages, forms, and API endpoints.
        Requires Burp Suite Professional.

        Args:
            url: Single seed URL to crawl
            urls: Multiple seed URLs to crawl
        """
        payload: dict = {}
        if urls:
            payload["urls"] = urls
        elif url:
            payload["url"] = url
        else:
            return "Error: Provide 'url' or 'urls'"

        data = await client.post("/api/scanner/crawl", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"Crawl started (ID: {data.get('scan_id')})\n"
            f"  {data.get('message', '')}\n\n"
            f"Use get_sitemap() to see discovered content."
        )

    @mcp.tool()
    async def get_scan_status() -> str:
        """Check the status of active and completed scans.
        Shows scan IDs, descriptions, request counts, issue counts, and status messages."""
        data = await client.get("/api/scanner/status")
        if "error" in data:
            return f"Error: {data['error']}"

        scans = data.get("scans", [])
        total_findings = data.get("total_scanner_findings", 0)

        if not scans:
            return f"No active scans. Total scanner findings: {total_findings}"

        lines = [f"Active Scans ({data.get('active_scans', 0)}):\n"]
        for scan in scans:
            lines.append(f"  [#{scan.get('scan_id')}] {scan.get('description')}")
            lines.append(f"    Started: {scan.get('started_at')}")
            if scan.get("status_message"):
                lines.append(f"    Status: {scan['status_message']}")
            if scan.get("request_count") is not None:
                lines.append(f"    Requests: {scan.get('request_count', 0)} | Insertion Points: {scan.get('insertion_point_count', 0)}")
            if scan.get("issue_count") is not None:
                lines.append(f"    Issues: {scan.get('issue_count', 0)} | Errors: {scan.get('error_count', 0)}")
            lines.append("")

        lines.append(f"Total scanner findings: {total_findings}")
        return "\n".join(lines)
