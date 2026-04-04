"""Tools for reading data from Burp Suite - proxy history, sitemap, scanner findings, scope."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.processing.formatters import format_proxy_table, format_findings


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_proxy_history(
        limit: int = 50,
        offset: int = 0,
        filter_url: str = "",
        filter_method: str = "",
        filter_status: str = "",
    ) -> str:
        """Get HTTP proxy history from Burp Suite.
        Returns a summary table of requests captured by Burp's proxy.
        Use filter_url to search by URL substring, filter_method for HTTP method (GET/POST/etc),
        filter_status for status code. Results are ordered newest-first."""
        params = {"limit": limit, "offset": offset}
        if filter_url:
            params["filter_url"] = filter_url
        if filter_method:
            params["filter_method"] = filter_method
        if filter_status:
            params["filter_status"] = filter_status

        data = await client.get("/api/proxy/history", params=params)
        if "error" in data:
            return f"Error: {data['error']}"
        return format_proxy_table(data)

    @mcp.tool()
    async def get_request_detail(index: int) -> str:
        """Get full request and response details for a specific proxy history item.
        Returns headers, body, status code. Use after get_proxy_history to inspect interesting requests."""
        data = await client.get(f"/api/proxy/history/{index}")
        if "error" in data:
            return f"Error: {data['error']}"

        lines = []
        lines.append(f"=== Request [{data.get('method')}] {data.get('url')} ===")
        lines.append("")

        # Request headers
        for h in data.get("request_headers", []):
            lines.append(f"  {h['name']}: {h['value']}")
        req_body = data.get("request_body", "")
        if req_body:
            lines.append(f"\n--- Request Body ({len(req_body)} chars) ---")
            lines.append(req_body[:5000])

        # Response
        lines.append(f"\n=== Response [{data.get('status_code')}] ({data.get('response_length', 0)} bytes, {data.get('mime_type', '')}) ===")
        for h in data.get("response_headers", []):
            lines.append(f"  {h['name']}: {h['value']}")
        resp_body = data.get("response_body", "")
        if resp_body:
            lines.append(f"\n--- Response Body ({len(resp_body)} chars) ---")
            lines.append(resp_body)

        return "\n".join(lines)

    @mcp.tool()
    async def get_scanner_findings(
        severity: str = "",
        confidence: str = "",
        limit: int = 100,
    ) -> str:
        """Get scanner/audit findings from Burp Suite Professional.
        Filter by severity (HIGH, MEDIUM, LOW, INFORMATION) and confidence (CERTAIN, FIRM, TENTATIVE).
        Returns vulnerability name, severity, URL, and evidence."""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        if confidence:
            params["confidence"] = confidence

        data = await client.get("/api/scanner/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"
        return format_findings(data)

    @mcp.tool()
    async def get_sitemap(url_prefix: str = "", limit: int = 200) -> str:
        """Get the site map from Burp Suite - all discovered URLs/endpoints.
        Filter by url_prefix to focus on a specific target. Shows methods, status codes, and response sizes."""
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
        """Get the current target scope from Burp Suite.
        Shows which hosts/URLs are in scope for testing."""
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
    async def check_scope(url: str) -> str:
        """Check if a specific URL is within the target scope."""
        data = await client.post("/api/scope/check", json={"url": url})
        if "error" in data:
            return f"Error: {data['error']}"

        in_scope = data.get("in_scope", False)
        return f"{url} is {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}"

    @mcp.tool()
    async def add_to_scope(url: str) -> str:
        """Add a URL or host to Burp's target scope.
        Use this to programmatically set the scope before scanning.

        Args:
            url: URL to include in scope (e.g. 'https://target.com')
        """
        data = await client.post("/api/scope/add", json={"url": url})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Added to scope: {url}")

    @mcp.tool()
    async def remove_from_scope(url: str) -> str:
        """Remove a URL or host from Burp's target scope.

        Args:
            url: URL to exclude from scope
        """
        data = await client.post("/api/scope/remove", json={"url": url})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Removed from scope: {url}")

    @mcp.tool()
    async def get_cookies(domain: str = "") -> str:
        """Get cookies from Burp's cookie jar.
        Shows cookie name, value, domain, path, and expiration.
        Useful for session analysis and auth testing.

        Args:
            domain: Optional domain filter (e.g. 'target.com')
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
            if len(value) > 38:
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
    async def get_websocket_history(limit: int = 50) -> str:
        """Get WebSocket message history from Burp's proxy.
        Shows message direction, payload, and size. Newest messages first.

        Args:
            limit: Maximum number of messages to return (default 50)
        """
        data = await client.get("/api/websocket/history", params={"limit": limit})
        if "error" in data:
            return f"Error: {data['error']}"

        messages = data.get("messages", [])
        if not messages:
            return "No WebSocket messages captured. WebSocket traffic must flow through Burp's proxy."

        lines = [f"WebSocket Messages ({data.get('total', 0)} total, showing {len(messages)}):\n"]
        for msg in messages:
            direction = msg.get("direction", "?")
            idx = msg.get("index", "?")
            length = msg.get("length", 0)
            payload = msg.get("payload", "")

            arrow = ">>" if "CLIENT" in str(direction).upper() else "<<"
            lines.append(f"[{idx}] {arrow} ({direction}, {length} bytes)")

            # Show payload with truncation
            if len(payload) > 200:
                lines.append(f"  {payload[:200]}...")
            else:
                lines.append(f"  {payload}")
            lines.append("")

        return "\n".join(lines)
