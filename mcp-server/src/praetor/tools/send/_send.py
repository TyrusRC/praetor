"""Fresh/modified HTTP send: raw, resend-with-modification, curl."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers
from ._format import _format_curl_response, _format_response


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_raw_request(
        raw: str,
        host: str,
        port: int = 443,
        https: bool = True,
        http_version: str = "",
        cookie_jar: bool = True,
    ) -> str:
        """Send a raw HTTP request through Burp for exact byte-level control.

        An absolute-URI request line (GET https://target/path) with a divergent
        Host header (routing-based SSRF / host-header attacks) is delivered
        byte-exact over a direct HTTP/1 socket — every Burp path re-serializes it
        to origin-form and defeats the attack. Such a send is Logger-visible, not
        in Proxy history.

        Args:
            raw: Complete raw HTTP request string (LF endings are normalised to CRLF)
            host: Target hostname (also the cookie-jar lookup key)
            port: Target port (default 443)
            https: Use HTTPS (default True)
            http_version: Pin the wire protocol for an ORIGIN-form request: "1"/"1.1"
                or "2". Empty = AUTO (Proxy-history visible). (Absolute-URI requests
                always go direct over HTTP/1 regardless.)
            cookie_jar: When true (default) and the raw request has no Cookie header,
                auto-attach the target host's cookies from Burp's cookie jar. The
                session cookie that gets a modified-Host request past the front-end
                belongs to the real service host and is easy to omit by hand — the
                response's `cookie_jar` note says what was attached or that the jar
                was empty. Set false for a deliberately unauthenticated raw send.
        """
        payload: dict = {
            "raw": raw,
            "host": host,
            "port": port,
            "https": https,
            "cookie_jar": cookie_jar,
        }
        if http_version:
            payload["http_version"] = http_version
        data = await client.post("/api/http/raw", json=payload)
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
        """Resend a proxy history request with modifications.

        Args:
            index: Proxy history index of the original request
            modify_headers: Headers to add/replace
            modify_body: New request body
            modify_path: New URL path
            modify_method: New HTTP method
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
        follow_redirects: bool = False,
        max_redirects: int = 10,
        bare_headers: bool = False,
        unsafe_headers: bool = False,
    ) -> str:
        """Flexible HTTP request through Burp with auth, cookies, and optional redirect following.

        Realistic browser headers are auto-injected unless already set or bare_headers=True; a saved profile (.burp-intel/<domain>/profile.json) overrides defaults. Caller-supplied headers/auth/bearer/cookies always win.

        Args:
            url: Target URL.
            method: HTTP method (GET/POST/PUT/DELETE/PATCH/...).
            headers: Custom headers dict.
            body: Raw request body string.
            data: Form-encoded data (auto-sets Content-Type).
            json_body: JSON body dict (auto-sets Content-Type).
            auth_user: Username for Basic auth.
            auth_pass: Password for Basic auth.
            bearer_token: Bearer token for Authorization header.
            cookies: Cookies dict.
            follow_redirects: Follow redirects (default False to prevent cross-scope leaks).
            max_redirects: Max redirect hops (default 10).
            bare_headers: Skip realistic-header injection (WAF detection / raw wire tests).
            unsafe_headers: Keep fingerprint but pass profile's Host/Content-Length/Transfer-Encoding/Content-Type through (header/host-header injection, HPP, smuggling).
        """
        merged = apply_realistic_headers(
            url, headers, bare=bare_headers, unsafe_headers=unsafe_headers,
        )
        payload: dict = {
            "method": method,
            "url": url,
            "follow_redirects": follow_redirects,
            "max_redirects": max_redirects,
        }
        if merged:
            payload["headers"] = merged
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
