"""Tools for correlating findings - search history, match scanner findings to endpoints."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def search_history(
        query: str,
        in_url: bool = True,
        in_request_body: bool = False,
        in_response_body: bool = False,
        method: str = "",
        status_code: int = 0,
        limit: int = 50,
    ) -> str:
        """Search proxy history for requests matching a query string.
        Search across URLs, request bodies, and response bodies.
        Use to find all requests related to a specific feature, parameter, or endpoint.

        Args:
            query: Search string (case-insensitive substring match)
            in_url: Search in URLs (default True)
            in_request_body: Search in request bodies
            in_response_body: Search in response bodies
            method: Filter by HTTP method
            status_code: Filter by response status code
            limit: Max results (default 50)
        """
        payload = {
            "query": query,
            "in_url": in_url,
            "in_request_body": in_request_body,
            "in_response_body": in_response_body,
            "limit": limit,
        }
        if method:
            payload["method"] = method
        if status_code:
            payload["status_code"] = status_code

        data = await client.post("/api/search/history", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        results = data.get("results", [])
        if not results:
            return f"No results found for '{query}'"

        lines = [f"Search results for '{query}' ({data.get('total_matches', 0)} matches):\n"]
        lines.append(f"{'INDEX':<8} {'METHOD':<8} {'STATUS':<8} URL")
        lines.append("-" * 80)
        for r in results:
            lines.append(f"{r['index']:<8} {r['method']:<8} {r.get('status_code', '-'):<8} {r['url']}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_findings_for_endpoint(url: str) -> str:
        """Get all findings (scanner + manual notes) related to a specific endpoint URL.
        Combines Burp scanner findings and user-saved notes for comprehensive view."""
        # Get scanner findings
        scanner_data = await client.get("/api/scanner/findings")
        notes_data = await client.get("/api/notes/findings", params={"endpoint": url})

        lines = [f"Findings for: {url}\n"]

        # Scanner findings matching this URL
        if "items" in scanner_data:
            matching = [f for f in scanner_data["items"] if url in str(f.get("base_url", ""))]
            if matching:
                lines.append(f"--- Scanner Findings ({len(matching)}) ---")
                for f in matching:
                    lines.append(f"  [{f.get('severity')}] {f.get('name')} (confidence: {f.get('confidence')})")
                    if f.get("detail"):
                        lines.append(f"    {f['detail'][:200]}")
                lines.append("")

        # Manual findings
        findings = notes_data.get("findings", []) if "findings" in notes_data else []
        if findings:
            lines.append(f"--- Manual Findings ({len(findings)}) ---")
            for f in findings:
                lines.append(f"  [{f.get('severity')}] {f.get('title')}")
                if f.get("description"):
                    lines.append(f"    {f['description'][:200]}")

        if len(lines) == 1:
            lines.append("No findings found for this endpoint.")

        return "\n".join(lines)

    @mcp.tool()
    async def get_response_diff(index1: int, index2: int) -> str:
        """Diff two proxy history responses to spot differences.
        Useful for comparing responses with/without auth, different parameter values, etc.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
        """
        data = await client.post("/api/search/response-diff", json={
            "index1": index1,
            "index2": index2,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Response Diff: #{data.get('index1')} vs #{data.get('index2')}"]
        lines.append(f"Status: {data.get('status1')} vs {data.get('status2')}")
        lines.append(f"Length: {data.get('length1')} vs {data.get('length2')}")
        lines.append(f"Differences: {data.get('total_differences', 0)}\n")

        diff_lines = data.get("diff_lines", [])
        if diff_lines:
            for line in diff_lines:
                lines.append(line)
        else:
            lines.append("Responses are identical.")

        return "\n".join(lines)
