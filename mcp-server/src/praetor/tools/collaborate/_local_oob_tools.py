"""MCP tools for the built-in OOB callback server (Community fallback)."""

from __future__ import annotations

import os
import time

from mcp.server.fastmcp import FastMCP

from ._local_oob import get_local_oob


def _detect_local_ip() -> str:
    """Best-effort local IP that a target on the same network can reach."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def register(mcp: FastMCP):

    @mcp.tool()
    async def start_oob_server(port: int = 0) -> str:
        """Start the built-in OOB HTTP callback server for blind vuln testing
        without Burp Collaborator (Community edition / air-gapped).

        The server records every inbound HTTP request. Use
        generate_collaborator_payload (which auto-falls-back here) to get a
        unique callback URL, inject it, then get_oob_interactions to check hits.

        Args:
            port: Listen port (default from PRAETOR_OOB_PORT env, or 9999).
                  Must be reachable from the target.
        """
        oob = get_local_oob()
        if port > 0:
            oob.port = port
        result = oob.start()
        if oob.running:
            ip = _detect_local_ip()
            return (
                f"{result}\n"
                f"Callback base URL: http://{ip}:{oob.port}/\n"
                f"Inject http://{ip}:{oob.port}/<unique-id> into blind payloads.\n"
                f"Poll with get_oob_interactions()."
            )
        return result

    @mcp.tool()
    async def stop_oob_server() -> str:
        """Stop the built-in OOB callback server."""
        oob = get_local_oob()
        if not oob.running:
            return "OOB server is not running."
        oob.stop()
        return "OOB server stopped."

    @mcp.tool()
    async def get_oob_interactions(interaction_id: str = "") -> str:
        """Check for OOB callback hits on the built-in server.

        Args:
            interaction_id: Filter to hits matching this ID (the path prefix
                from the generated URL). Empty returns all hits.
        """
        oob = get_local_oob()
        if not oob.running:
            return "OOB server is not running. Call start_oob_server() first."
        hits = oob.get_hits(interaction_id)
        if not hits:
            if interaction_id:
                return f"No OOB hits for interaction {interaction_id}. Total hits on server: {oob.hit_count}."
            return "No OOB hits recorded yet."

        lines = [f"OOB Interactions ({len(hits)} hit{'s' if len(hits) != 1 else ''}):\n"]
        for h in hits:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h.timestamp))
            lines.append(f"  [{h.method}] {h.path}")
            lines.append(f"    From: {h.client_ip}")
            lines.append(f"    Time: {ts}")
            if h.query:
                lines.append(f"    Query: {h.query}")
            if h.body:
                lines.append(f"    Body: {h.body[:500]}")
            host = h.headers.get("Host", "")
            if host:
                lines.append(f"    Host: {host}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    async def generate_oob_payload() -> str:
        """Generate a callback URL on the built-in OOB server.

        Auto-starts the server if not running. Use this when Burp Collaborator
        is unavailable (Community edition).
        """
        oob = get_local_oob()
        if not oob.running:
            result = oob.start()
            if not oob.running:
                return f"Failed to start OOB server: {result}"
        uid = oob.generate_id()
        ip = _detect_local_ip()
        url = f"http://{ip}:{oob.port}/{uid}"
        return (
            f"OOB Callback URL: {url}\n"
            f"Interaction ID: {uid}\n\n"
            f"Inject this URL into blind payloads (SSRF, XXE, blind SQLi, etc.).\n"
            f"Poll with get_oob_interactions(interaction_id='{uid}')."
        )
