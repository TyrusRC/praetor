"""test_websocket — WebSocket auth/origin attack matrix at the upgrade handshake.

WebSocket security mostly fails at the HTTP upgrade request, not after.
The attack surface:

  §1 Origin bypass — server doesn't validate Origin header. Cross-Site
     WebSocket Hijacking (CSWSH) — attacker page opens WS as victim using
     ambient cookies.
  §2 Missing Origin — server accepts the upgrade with no Origin at all.
  §3 Wildcard Origin — server reflects whatever Origin was sent.
  §4 Token in URL — auth token in the ws:// URL. Logged in proxies / server
     access logs / Referer. Often paired with no other auth.
  §5 No auth required — upgrade succeeds with no cookie / no bearer.
  §6 Subprotocol negotiation flaw — server accepts unknown subprotocols.

Every probe is an HTTP/1.1 upgrade request (101 Switching Protocols on
success). No third-party covers this matrix programmatically.
"""

from __future__ import annotations

import base64
import os
import re
from urllib.parse import urlparse, urlunparse

from mcp.server.fastmcp import FastMCP

from ._send import send_probe


def _ws_key() -> str:
    """Generate a Sec-WebSocket-Key (16 random bytes, base64)."""
    return base64.b64encode(os.urandom(16)).decode()


def _to_http(url: str) -> str:
    """Convert ws:// / wss:// to http:// / https:// for the HTTP upgrade."""
    if url.startswith("ws://"):
        return "http://" + url[5:]
    if url.startswith("wss://"):
        return "https://" + url[6:]
    return url


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_websocket(  # cost: low (~6 requests)
        ws_url: str,
        cookies: dict | None = None,
        bearer_token: str = "",
        subprotocols: list[str] | None = None,
    ) -> str:
        """WebSocket-upgrade attack matrix. All probes sent as HTTP/1.1
        upgrade requests through Burp.

        Args:
            ws_url: WebSocket URL (ws:// or wss://; http:// also accepted)
            cookies: Session cookies (test CSWSH — victim cookies + attacker Origin)
            bearer_token: Optional bearer for Authorization header
            subprotocols: Optional Sec-WebSocket-Protocol values to test
        """
        http_url = _to_http(ws_url)
        parsed = urlparse(http_url)
        host = parsed.netloc.split(":")[0]
        legitimate_origin = f"{parsed.scheme}://{host}"

        base_headers = {
            "Host": parsed.netloc,
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Key": _ws_key(),
            "Sec-WebSocket-Version": "13",
        }

        lines = [f"test_websocket {ws_url}\n"]
        bypasses: list[str] = []

        token_in_url = bool(re.search(
            r"[?&](token|access_token|auth|session|sid|jwt|bearer)=",
            ws_url, re.IGNORECASE))
        if token_in_url:
            bypasses.append(
                f"§4 token in URL — leaks to proxy logs / Referer / browser history")
            lines.append("  §4 Token in URL:  *** PRESENT *** — auth in "
                         "ws:// URL is logged everywhere it transits")
            lines.append("")

        # §1 Hostile Origin
        h1 = {**base_headers, "Origin": "https://evil.tld",
              "Sec-WebSocket-Key": _ws_key()}
        r1 = await send_probe("GET", http_url, h1, cookies=cookies,
                              bearer=bearer_token)
        s1 = r1.get("status_code", 0)
        idx1 = r1.get("history_index", -1)
        lines.append(f"  §1 Hostile Origin (https://evil.tld):  {s1} (#{idx1})")
        if s1 == 101:
            bypasses.append(f"§1 hostile Origin accepted (#{idx1}) — CSWSH "
                            f"possible: attacker page opens WS as victim")

        # §2 Missing Origin
        h2 = {**base_headers, "Sec-WebSocket-Key": _ws_key()}
        r2 = await send_probe("GET", http_url, h2, cookies=cookies,
                              bearer=bearer_token)
        s2 = r2.get("status_code", 0)
        idx2 = r2.get("history_index", -1)
        lines.append(f"  §2 No Origin header:                   {s2} (#{idx2})")
        if s2 == 101:
            bypasses.append(f"§2 missing Origin accepted (#{idx2}) — "
                            f"non-browser clients connect without challenge")

        # §3 Wildcard / null Origin
        h3 = {**base_headers, "Origin": "null",
              "Sec-WebSocket-Key": _ws_key()}
        r3 = await send_probe("GET", http_url, h3, cookies=cookies,
                              bearer=bearer_token)
        s3 = r3.get("status_code", 0)
        idx3 = r3.get("history_index", -1)
        lines.append(f"  §3 Origin: null:                       {s3} (#{idx3})")
        if s3 == 101:
            bypasses.append(f"§3 Origin: null accepted (#{idx3}) — sandboxed "
                            f"iframe / data: URL can open WS")

        # §5 No auth at all
        h5 = {**base_headers, "Origin": legitimate_origin,
              "Sec-WebSocket-Key": _ws_key()}
        r5 = await send_probe("GET", http_url, h5)
        s5 = r5.get("status_code", 0)
        idx5 = r5.get("history_index", -1)
        lines.append(f"  §5 No auth (anon):                     {s5} (#{idx5})")
        if s5 == 101:
            bypasses.append(f"§5 anonymous WS upgrade accepted (#{idx5}) — "
                            f"unauthenticated access to message stream")

        # §6 Subprotocol flaw — accept whatever was offered
        protos_to_test = subprotocols or [
            "graphql-ws", "echo-protocol", "v1", "admin", "noop",
        ]
        for proto in protos_to_test:
            h6 = {**base_headers, "Origin": legitimate_origin,
                  "Sec-WebSocket-Key": _ws_key(),
                  "Sec-WebSocket-Protocol": proto}
            r6 = await send_probe("GET", http_url, h6, cookies=cookies,
                                  bearer=bearer_token)
            s6 = r6.get("status_code", 0)
            idx6 = r6.get("history_index", -1)
            # Inspect server's chosen protocol header
            chosen = ""
            for h in r6.get("response_headers", []) or []:
                if h.get("name", "").lower() == "sec-websocket-protocol":
                    chosen = h.get("value", "")
            marker = ""
            if s6 == 101 and chosen == proto:
                marker = "  *** server accepted the bogus subprotocol ***"
                bypasses.append(f"§6 subprotocol {proto!r} accepted (#{idx6})")
            lines.append(f"  §6 subproto={proto!r:<20} -> {s6} (#{idx6}) "
                         f"chosen={chosen!r}{marker}")

        lines.append("")
        if bypasses:
            lines.append(f"FINDINGS ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("Save guidance:")
            lines.append("  vuln_type='cswsh' severity='high' for §1/§3 when "
                         "WS carries state-changing operations")
            lines.append("  vuln_type='ws_no_auth' severity='high' for §5 when "
                         "stream leaks per-user data")
            lines.append("  vuln_type='ws_token_in_url' severity='medium' for §4")
        else:
            lines.append("WebSocket upgrade defenses intact across Origin / "
                         "auth / subprotocol axes.")

        return "\n".join(lines)
