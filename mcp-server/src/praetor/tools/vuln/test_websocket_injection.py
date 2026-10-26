"""WebSocket message-payload injection fuzzer.

Connects to a WebSocket, sends injection payloads through the message stream,
and analyzes responses for error signatures / reflection / anomalies. Covers
the gap that test_websocket (upgrade-handshake only) and vigil (HTTP only)
leave open: server-side processing of WS message content.

Attack classes: SQLi, XSS (if messages render in a web view), CMDi, SSTI,
NoSQL, LDAP, XPath, path traversal through WS frames.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing._verdict import make_verdict, verdict_from_tally

# Compact payload set — one high-confidence probe per class.
_PAYLOADS: list[dict] = [
    {"class": "sqli", "payload": "' OR 1=1--", "markers": ["sql", "syntax", "query", "mysql", "postgres", "sqlite", "oracle", "mssql", "unexpected"]},
    {"class": "sqli_time", "payload": "' AND SLEEP(3)--", "markers": ["sql", "syntax"]},
    {"class": "xss", "payload": "<img src=x onerror=alert(1)>", "markers": ["<img", "onerror", "alert"]},
    {"class": "cmdi", "payload": ";id;", "markers": ["uid=", "gid=", "groups="]},
    {"class": "cmdi", "payload": "|cat /etc/passwd|", "markers": ["root:", "/bin/"]},
    {"class": "ssti", "payload": "{{7*7}}", "markers": ["49"]},
    {"class": "ssti", "payload": "${7*7}", "markers": ["49"]},
    {"class": "nosql", "payload": '{"$gt":""}', "markers": ["$gt", "operator", "query"]},
    {"class": "path_traversal", "payload": "../../../../etc/passwd", "markers": ["root:", "/bin/"]},
    {"class": "ldap", "payload": "*)(&", "markers": ["ldap", "distinguished", "invalid filter"]},
    {"class": "xxe", "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "markers": ["root:", "/bin/"]},
    {"class": "log4shell", "payload": "${jndi:ldap://127.0.0.1/x}", "markers": ["jndi", "lookup"]},
]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_websocket_injection(
        ws_url: str,
        message_template: str = "",
        inject_field: str = "",
        cookies: dict | None = None,
        bearer_token: str = "",
        categories: list[str] | None = None,
    ) -> dict:
        """Fuzz WebSocket message payloads with injection probes. Returns VerdictResult.

        Connects via Burp's WebSocket tools, sends each payload as a WS
        message, reads the response, and checks for error/reflection markers.

        Args:
            ws_url: WebSocket URL (ws:// or wss://).
            message_template: A sample message the server accepts. If JSON,
                inject_field names the key to replace with payloads. If empty,
                payloads are sent as raw messages.
            inject_field: JSON key in message_template to inject into.
            cookies: Session cookies for authenticated WS.
            bearer_token: Bearer token for the upgrade handshake.
            categories: Filter payload classes (sqli, xss, cmdi, ssti, nosql,
                path_traversal, ldap, xxe, log4shell). Default: all.
        """
        cats = set(c.lower() for c in (categories or []))
        payloads = [p for p in _PAYLOADS if not cats or p["class"] in cats]

        # Parse template
        template_json = None
        if message_template.strip():
            try:
                template_json = json.loads(message_template)
            except json.JSONDecodeError:
                pass

        # Connect
        conn_name = "ws-inject-test"
        conn = await client.post("/api/websocket/connect", json={
            "url": ws_url, "name": conn_name,
            "cookies": cookies or {}, "bearer_token": bearer_token,
        })
        if "error" in conn:
            return make_verdict(
                "websocket_injection", ws_url, "",
                "error", f"Connect failed: {conn['error']}", [],
            )

        # Capture baseline
        baseline_msg = message_template or '{"test":"baseline"}'
        await client.post("/api/websocket/send", json={
            "name": conn_name, "message": baseline_msg,
        })
        import asyncio
        await asyncio.sleep(0.5)
        baseline_resp = await client.get(f"/api/websocket/history?name={conn_name}&limit=5")
        baseline_messages = baseline_resp.get("messages", [])
        baseline_body = ""
        for m in reversed(baseline_messages):
            if m.get("direction") == "SERVER_TO_CLIENT":
                baseline_body = m.get("payload", "")
                break

        hits: list[str] = []
        details: list[str] = []

        for p in payloads:
            # Build injection message
            if template_json and inject_field:
                msg = json.loads(json.dumps(template_json))
                msg[inject_field] = p["payload"]
                send_msg = json.dumps(msg)
            else:
                send_msg = p["payload"]

            await client.post("/api/websocket/send", json={
                "name": conn_name, "message": send_msg,
            })
            await asyncio.sleep(0.3)

            # Read response
            resp = await client.get(f"/api/websocket/history?name={conn_name}&limit=5")
            messages = resp.get("messages", [])
            reply = ""
            for m in reversed(messages):
                if m.get("direction") == "SERVER_TO_CLIENT":
                    reply = m.get("payload", "")
                    break

            # Check markers
            reply_lower = reply.lower()
            matched = [mk for mk in p["markers"] if mk.lower() in reply_lower]

            # Check for reflection (payload appears in response)
            reflected = p["payload"] in reply or p["payload"].lower() in reply_lower

            # Check for anomaly vs baseline
            anomaly = (len(reply) != len(baseline_body) and
                       abs(len(reply) - len(baseline_body)) > 50)

            if matched or reflected:
                hit = f"{p['class']}: payload={p['payload']!r}, markers={matched}, reflected={reflected}"
                hits.append(hit)
                details.append(hit)
            elif anomaly:
                details.append(
                    f"{p['class']}: anomaly (len delta {len(reply) - len(baseline_body)}) "
                    f"payload={p['payload']!r}"
                )

        # Close
        await client.post("/api/websocket/close", json={"name": conn_name})

        return verdict_from_tally(
            hits,
            vuln_type="websocket_injection",
            endpoint=ws_url,
            parameter=inject_field or "(raw message)",
            detail="\n".join(details) if details else "No injection markers or reflection detected.",
        )
