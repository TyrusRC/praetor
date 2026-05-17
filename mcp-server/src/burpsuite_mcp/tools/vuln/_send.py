"""Shared HTTP helper for vuln/ orchestrators. Routes via Burp HTTP client
(/api/http/curl) so every probe carries a real history_index."""

from __future__ import annotations

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers


async def send_probe(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    json_body: dict | None = None,
    cookies: dict | None = None,
    bearer: str = "",
    follow_redirects: bool = False,
) -> dict:
    """Send one request through Burp. Realistic headers applied unless caller
    supplies a complete headers dict that intentionally overrides them."""
    merged = apply_realistic_headers(url, headers or {})
    if cookies:
        merged["Cookie"] = "; ".join(
            f"{k}={str(v).replace(';', '%3B')}" for k, v in cookies.items())
    if bearer:
        merged["Authorization"] = f"Bearer {bearer}"

    payload: dict = {
        "method": method,
        "url": url,
        "headers": merged,
        "follow_redirects": follow_redirects,
    }
    if body:
        payload["body"] = body
    if json_body is not None:
        payload["json"] = json_body
    return await client.post("/api/http/curl", json=payload)
