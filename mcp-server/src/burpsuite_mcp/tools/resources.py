"""Tools for accessing static resources (JS/CSS/source maps) for analysis."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def fetch_resource(url: str) -> str:
        """Fetch a static resource (JS/CSS) through Burp and return its content.

        Args:
            url: Full URL of the resource to fetch
        """
        data = await client.post("/api/resources/fetch", json={"url": url})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Fetched: {url}"]
        lines.append(f"Status: {data.get('status_code', '?')}")
        lines.append(f"Size: {data.get('content_length', 0)} bytes")
        lines.append(f"Content-Type: {data.get('content_type', '?')}")

        if data.get("proxy_index") is not None:
            lines.append(f"Proxy History Index: {data['proxy_index']} (use this for analysis tools)")

        content = data.get("content", "")
        if content:
            lines.append(f"\n--- Content ({len(content)} chars) ---")
            lines.append(content)

        return "\n".join(lines)

    @mcp.tool()
    async def fetch_page_resources(
        index: int = -1,
        url: str = "",
    ) -> str:
        """Fetch all static resources linked from a page (script/link/map refs). Provide index or url.

        Args:
            index: Proxy history index of the HTML page
            url: URL of the page to parse for resources
        """
        payload: dict = {}
        if index >= 0:
            payload["index"] = index
        elif url:
            payload["url"] = url
        else:
            return "Error: Provide 'index' or 'url'"

        data = await client.post("/api/resources/fetch-page", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        fetched = data.get("fetched", [])
        already_cached = data.get("already_in_history", [])
        failed = data.get("failed", [])

        lines = [f"Page Resource Fetch Results:\n"]
        lines.append(f"  Already in history: {len(already_cached)}")
        lines.append(f"  Newly fetched: {len(fetched)}")
        lines.append(f"  Failed: {len(failed)}")
        lines.append("")

        if fetched:
            lines.append("--- Newly Fetched ---")
            for r in fetched:
                lines.append(f"  [{r.get('proxy_index', '?')}] {r.get('url', '')} ({r.get('size', 0)} bytes)")

        if already_cached:
            lines.append("--- Already in History ---")
            for r in already_cached:
                lines.append(f"  [{r.get('index', '?')}] {r.get('url', '')}")

        if failed:
            lines.append("--- Failed ---")
            for r in failed:
                lines.append(f"  {r.get('url', '')}: {r.get('error', 'unknown error')}")

        lines.append("\nUse extract_js_secrets(index) or analyze_dom(index) on fetched resources.")
        return "\n".join(lines)
