"""Read: sitemap, scope, cookies, websocket history."""

from mcp.server.fastmcp import FastMCP

from praetor import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_sitemap(url_prefix: str = "", limit: int = 30) -> str:
        """Get Burp's site map showing all discovered URLs/endpoints.

        Args:
            url_prefix: Filter by URL prefix
            limit: Max entries to return (default 30 — pass higher explicitly when you need more)
        """
        params = {"limit": limit}
        if url_prefix:
            params["prefix"] = url_prefix

        data = await client.get("/api/sitemap", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        items = data.get("items", [])
        if not items:
            return "Sitemap is empty. Browse the target in Burp first."

        lines = [f"Sitemap ({data.get('total_returned', 0)} entries):"]
        lines.append(f"{'METHOD':<8} {'STATUS':<7} {'SIZE':<8} URL")
        lines.append("-" * 80)
        for item in items:
            status = item.get("status_code", "-")
            size = item.get("response_length", 0)
            lines.append(f"{item['method']:<8} {status:<7} {size:<8} {item['url']}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_scope() -> str:
        """Get the current target scope configuration from Burp Suite."""
        data = await client.get("/api/scope")
        if "error" in data:
            return f"Error: {data['error']}"

        hosts = data.get("in_scope_hosts", [])
        total = data.get("total_in_scope_urls", 0)

        if not hosts:
            return "No scope defined. Add targets to scope in Burp Suite."

        lines = [f"Target Scope ({total} URLs in scope):"]
        for h in hosts:
            lines.append(f"  - {h}")
        return "\n".join(lines)

    @mcp.tool()
    async def check_scope(url: str) -> dict:
        """Check if a specific URL is within the target scope.

        Returns structured dict: {url, in_scope: bool, human_summary} or {error}.
        Pre-flight gate for Rule 1 — runs on every fresh domain.

        Args:
            url: URL to check
        """
        data = await client.post("/api/scope/check", json={"url": url})
        if "error" in data:
            return {"error": data["error"]}

        in_scope = data.get("in_scope", False)
        return {
            "url": url,
            "in_scope": in_scope,
            "human_summary": f"{url} is {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}",
        }

    @mcp.tool()
    async def get_cookies(domain: str = "", full_values: bool = False) -> str:
        """Get cookies from Burp's cookie jar.

        Args:
            domain: Filter by domain
            full_values: Show complete cookie values without truncation
        """
        params = {}
        if domain:
            params["domain"] = domain

        data = await client.get("/api/cookies", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        cookies = data.get("cookies", [])
        if not cookies:
            return f"No cookies found{' for domain ' + domain if domain else ''}."

        lines = [f"Cookies ({data.get('total', 0)} total):\n"]
        lines.append(f"{'NAME':<25} {'VALUE':<40} {'DOMAIN':<25} PATH")
        lines.append("-" * 100)
        for c in cookies:
            name = c.get("name", "")[:23]
            value = c.get("value", "")
            if not full_values and len(value) > 38:
                value = value[:36] + ".."
            domain_val = c.get("domain", "")[:23]
            path = c.get("path", "/")
            lines.append(f"{name:<25} {value:<40} {domain_val:<25} {path}")

            # Flag security issues
            exp = c.get("expiration")
            if exp:
                lines.append(f"  {'  Expires: ' + str(exp)}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_websocket_history(
        limit: int = 50,
        offset: int = 0,
        direction: str = "",
        filter_payload: str = "",
        filter_url: str = "",
        since_index: int = -1,
    ) -> str:
        """Get WebSocket message history from Burp's proxy with filters.

        Args:
            limit: Max messages to return
            offset: Pagination offset
            direction: Filter by direction — 'client' (outgoing) or 'server' (incoming)
            filter_payload: Substring filter applied to message payload (case-insensitive)
            filter_url: Substring filter applied to the WebSocket connection URL
            since_index: Only return messages with index > since_index (poll for new traffic)
        """
        params: dict = {"limit": limit, "offset": offset}
        if direction:
            params["direction"] = direction
        if filter_payload:
            params["filter_payload"] = filter_payload
        if filter_url:
            params["filter_url"] = filter_url
        if since_index >= 0:
            params["since_index"] = since_index

        data = await client.get("/api/websocket/history", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        messages = data.get("messages", [])
        if not messages:
            hint = " Try clearing filters." if (direction or filter_payload or filter_url or since_index >= 0) else ""
            return f"No WebSocket messages captured.{hint} WebSocket traffic must flow through Burp's proxy."

        lines = [f"WebSocket Messages ({data.get('total', 0)} total, showing {len(messages)}):\n"]
        for msg in messages:
            d = msg.get("direction", "?")
            idx = msg.get("index", "?")
            length = msg.get("length", 0)
            payload = msg.get("payload", "")
            url = msg.get("url", "")

            arrow = ">>" if "CLIENT" in str(d).upper() else "<<"
            url_part = f" {url}" if url else ""
            lines.append(f"[{idx}] {arrow} ({d}, {length} bytes){url_part}")

            if len(payload) > 200:
                lines.append(f"  {payload[:200]}...")
            else:
                lines.append(f"  {payload}")
            lines.append("")

        return "\n".join(lines)
