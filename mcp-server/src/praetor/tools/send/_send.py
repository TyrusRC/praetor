"""Fresh/modified HTTP send: raw, resend-with-modification, curl."""

import asyncio
from collections import Counter

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers
from ._format import _format_curl_response, _format_response

_MAX_RAW_REPEAT = 500


def _format_repeat_summary(count: int, http_version: str,
                           codes: Counter, locations: Counter,
                           errors: Counter) -> str:
    """Aggregate an N-shot raw send into a status histogram.

    Request-smuggling desync attacks (capture-request / queue-poison) need the
    same byte-exact request fired many times to catch an intermittent victim on
    a poisoned back-end connection. Looping keeps every send inside Burp
    (Logger-visible) instead of forcing a raw-socket script that bypasses it.
    """
    lines = [f"Repeated raw send x{count} (http_version={http_version or 'auto'})"]
    if codes:
        lines.append("Status histogram: " + ", ".join(
            f"{k}:{v}" for k, v in sorted(codes.items(), key=lambda x: -x[1])))
    if locations:
        lines.append("Redirect Location(s): " + "; ".join(
            f"{v}x {loc}" for loc, v in locations.most_common(5)))
    if errors:
        lines.append("Errors: " + ", ".join(f"{k} ({v})" for k, v in errors.items()))
    lines.append("Responses are in Burp Logger (direct sends are not in Proxy history).")
    return "\n".join(lines)


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_raw_request(
        raw: str,
        host: str,
        port: int = 443,
        https: bool = True,
        http_version: str = "",
        cookie_jar: bool = True,
        count: int = 1,
        interval_ms: int = 0,
    ) -> str:
        """Send a raw HTTP request through Burp for exact byte-level control.

        An absolute-URI request line (GET https://target/path) with a divergent
        Host header (routing-based SSRF / host-header attacks) is delivered
        byte-exact over a direct HTTP/1 socket — every Burp path re-serializes it
        to origin-form and defeats the attack. Such a send is Logger-visible, not
        in Proxy history.

        A direct send has no proxy_history_index, but IS still citable: the
        response carries a `send_ref` ('send-N') that save_finding accepts via
        evidence={'send_ref': 'send-N'}. Fetch the stored request/response back
        with get_sent_request(send_ref).

        Args:
            raw: Complete raw HTTP request string (LF endings are normalised to CRLF)
            host: Target hostname (also the cookie-jar lookup key)
            port: Target port (default 443)
            https: Use HTTPS (default True)
            http_version: "1"/"1.1" or "2" pins the wire protocol for an ORIGIN-form
                request. "direct" forces a byte-exact direct HTTP/1 socket for ANY
                request — required for request smuggling (CL.TE / TE.CL): Burp/Montoya
                otherwise "fix" a request carrying both Content-Length and
                Transfer-Encoding (recompute the length or drop TE) and kill the
                desync. Empty = AUTO (Proxy-history visible). (Absolute-URI requests
                always go direct regardless.) A direct send is Logger-visible, not in
                Proxy history.
            cookie_jar: When true (default) and the raw request has no Cookie header,
                auto-attach the target host's cookies from Burp's cookie jar. The
                session cookie that gets a modified-Host request past the front-end
                belongs to the real service host and is easy to omit by hand — the
                response's `cookie_jar` note says what was attached or that the jar
                was empty. Set false for a deliberately unauthenticated raw send.
            count: Fire the SAME request this many times (default 1). >1 returns a
                status histogram instead of one response body — for request-smuggling
                desync attacks that must repeat to catch an intermittent victim on a
                poisoned back-end connection. Keeps the loop inside Burp (Logger-
                visible) rather than a raw-socket script that bypasses it. Capped at
                500.
            interval_ms: Delay between repeats when count>1 (default 0). A few hundred
                ms widens the window for a victim's request to land on a poisoned
                connection before the next self-send fills it.
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

        if count and count > 1:
            count = min(count, _MAX_RAW_REPEAT)
            codes: Counter = Counter()
            locations: Counter = Counter()
            errors: Counter = Counter()
            for i in range(count):
                d = await client.post("/api/http/raw", json=payload)
                if "error" in d:
                    errors[str(d["error"])[:60]] += 1
                else:
                    codes[d.get("status_code", "N/A")] += 1
                    loc = next((h["value"] for h in d.get("response_headers", [])
                                if h.get("name", "").lower() == "location"), None)
                    if loc:
                        locations[loc] += 1
                if interval_ms > 0 and i < count - 1:
                    await asyncio.sleep(interval_ms / 1000)
            return _format_repeat_summary(count, http_version, codes, locations, errors)

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

    @mcp.tool()
    async def get_sent_request(send_ref: str) -> str:
        """Fetch a stored direct send by its send_ref handle.

        Direct sends (request smuggling, absolute-target SSRF, pinned HTTP
        version) bypass Burp's proxy history, so they have no
        proxy_history_index. send_raw_request returns a `send_ref` ('send-N')
        for each; this fetches the full stored request/response. The send is
        citable in save_finding as evidence={'send_ref': 'send-N'}.

        Args:
            send_ref: The 'send-N' handle from a direct send's response.
        """
        data = await client.get(f"/api/http/stored/{send_ref}")
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_response(data)
