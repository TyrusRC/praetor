"""Tools for sending HTTP requests through Burp Suite - appears in HTTP history."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_http_request(
        method: str,
        url: str,
        headers: dict | None = None,
        body: str = "",
    ) -> str:
        """Send an HTTP request through Burp Suite's HTTP stack.
        The request appears in Burp's HTTP history and gets passive-scanned.
        Use this instead of curl - all traffic flows through Burp for visibility.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Full URL (e.g. https://example.com/api/users)
            headers: Optional dict of headers (e.g. {"Authorization": "Bearer xxx"})
            body: Optional request body string
        """
        payload = {"method": method, "url": url}
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body

        data = await client.post("/api/http/send", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return _format_response(data)

    @mcp.tool()
    async def send_raw_request(
        raw: str,
        host: str,
        port: int = 443,
        https: bool = True,
    ) -> str:
        """Send a raw HTTP request through Burp Suite.
        Use when you need exact control over the request bytes (e.g. request smuggling tests).
        The raw string should be a complete HTTP request with CRLF line endings.

        Args:
            raw: Complete raw HTTP request string
            host: Target hostname
            port: Target port (default 443)
            https: Use HTTPS (default True)
        """
        data = await client.post("/api/http/raw", json={
            "raw": raw,
            "host": host,
            "port": port,
            "https": https,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_response(data)

    @mcp.tool()
    async def resend_with_modification(
        index: int,
        modify_headers: dict | None = None,
        modify_body: str = "",
        modify_path: str = "",
        modify_method: str = "",
    ) -> str:
        """Resend a proxy history request with modifications through Burp.
        Takes a request by index and applies changes before sending.
        Perfect for testing parameter tampering, auth bypass, injection payloads.

        Args:
            index: Proxy history index of the original request
            modify_headers: Dict of headers to add/replace
            modify_body: New request body (replaces original)
            modify_path: New URL path (replaces original)
            modify_method: New HTTP method (replaces original)
        """
        payload: dict = {"index": index}
        if modify_headers:
            payload["modify_headers"] = modify_headers
        if modify_body:
            payload["modify_body"] = modify_body
        if modify_path:
            payload["modify_path"] = modify_path
        if modify_method:
            payload["modify_method"] = modify_method

        data = await client.post("/api/http/resend", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_response(data)

    @mcp.tool()
    async def send_to_repeater(index: int, tab_name: str = "") -> str:
        """Send a proxy history request to Burp's Repeater tool for manual testing.

        Args:
            index: Proxy history index of the request
            tab_name: Optional name for the Repeater tab
        """
        payload: dict = {"index": index}
        if tab_name:
            payload["tab_name"] = tab_name

        data = await client.post("/api/http/repeater", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Repeater")

    @mcp.tool()
    async def send_to_intruder(index: int) -> str:
        """Send a proxy history request to Burp's Intruder tool for automated testing.

        Args:
            index: Proxy history index of the request
        """
        data = await client.post("/api/http/intruder", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Intruder")


    @mcp.tool()
    async def curl_request(
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str = "",
        data: str = "",
        json_body: dict | None = None,
        auth_user: str = "",
        auth_pass: str = "",
        bearer_token: str = "",
        cookies: dict | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
    ) -> str:
        """Send HTTP requests through Burp like curl/httpx - with redirect following, auth, and cookies.
        All requests flow through Burp's HTTP stack (visible in HTTP history, passive-scanned).

        This is the most flexible request tool - use it like curl:
        - Auto-follows redirects and shows the redirect chain
        - Supports Basic auth, Bearer tokens, custom cookies
        - Shortcuts for JSON and form-encoded data
        - Every request appears in Burp's proxy history

        Args:
            url: Target URL (e.g. 'https://target.com/api/users')
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            headers: Custom headers dict (e.g. {"X-Custom": "value"})
            body: Raw request body string
            data: Form-encoded data (sets Content-Type: application/x-www-form-urlencoded)
            json_body: JSON body dict (sets Content-Type: application/json)
            auth_user: Username for Basic auth
            auth_pass: Password for Basic auth
            bearer_token: Bearer token for Authorization header
            cookies: Cookies dict (e.g. {"session": "abc123"})
            follow_redirects: Follow HTTP redirects (default True)
            max_redirects: Max redirect hops (default 10)
        """
        payload: dict = {
            "method": method,
            "url": url,
            "follow_redirects": follow_redirects,
            "max_redirects": max_redirects,
        }
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body
        if data:
            payload["data"] = data
        if json_body:
            payload["json"] = json_body
        if auth_user and auth_pass:
            payload["auth_user"] = auth_user
            payload["auth_pass"] = auth_pass
        if bearer_token:
            payload["bearer_token"] = bearer_token
        if cookies:
            payload["cookies"] = cookies

        resp = await client.post("/api/http/curl", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        return _format_curl_response(resp)


def _format_curl_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]

    redirects = data.get("redirects_followed", 0)
    if redirects > 0:
        lines.append(f"Redirects followed: {redirects}")
        chain = data.get("redirect_chain", [])
        for hop in chain:
            lines.append(f"  {hop.get('status')} -> {hop.get('location')}")

    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    resp_headers = data.get("response_headers", [])
    if resp_headers:
        lines.append("\n--- Response Headers ---")
        for h in resp_headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(body)

    return "\n".join(lines)


def _format_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]
    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    headers = data.get("response_headers", [])
    if headers:
        lines.append("\n--- Response Headers ---")
        for h in headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(body)

    return "\n".join(lines)
