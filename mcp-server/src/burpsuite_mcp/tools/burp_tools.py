"""Burp Suite native tool integrations — WebSocket send, Organizer, Decoder, Project, Logger, Intruder config."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    # ── WebSocket Send ──────────────────────────────────────────

    @mcp.tool()
    async def websocket_connect(url: str, name: str = "") -> str:
        """Open a WebSocket connection through Burp's proxy.

        Args:
            url: WebSocket URL (ws:// or wss://)
            name: Connection name for reference
        """
        payload: dict = {"url": url}
        if name:
            payload["name"] = name
        data = await client.post("/api/websocket-send/connect", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return f"WebSocket connected: {data.get('name', '?')} -> {url}"

    @mcp.tool()
    async def websocket_send_message(name: str, message: str) -> str:
        """Send a text message on an open WebSocket connection.

        Args:
            name: Connection name from websocket_connect
            message: Text message to send
        """
        data = await client.post("/api/websocket-send/send", json={
            "name": name, "message": message,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Sent to '{name}': {data.get('message_sent', '')[:100]} (total: {data.get('total_sent', 0)})"

    @mcp.tool()
    async def websocket_close(name: str) -> str:
        """Close a WebSocket connection.

        Args:
            name: Connection name to close
        """
        data = await client.post("/api/websocket-send/close", json={"name": name})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"WebSocket '{name}' closed")

    @mcp.tool()
    async def websocket_list_connections() -> str:
        """List all open WebSocket connections."""
        data = await client.get("/api/websocket-send/connections")
        if "error" in data:
            return f"Error: {data['error']}"

        conns = data.get("connections", [])
        if not conns:
            return "No open WebSocket connections"

        lines = [f"WebSocket Connections ({data.get('count', len(conns))}):"]
        for c in conns:
            lines.append(f"  [{c.get('name')}] {c.get('url')} (sent: {c.get('messages_sent', 0)})")
        return "\n".join(lines)

    # ── Organizer ───────────────────────────────────────────────

    @mcp.tool()
    async def send_to_organizer(index: int) -> str:
        """Send a proxy history item to Burp's Organizer tab.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/organizer/send", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Sent #{index} to Organizer")

    @mcp.tool()
    async def send_bulk_to_organizer(indices: list[int]) -> str:
        """Send multiple proxy history items to Burp's Organizer at once.

        Args:
            indices: List of proxy history indices to send
        """
        data = await client.post("/api/organizer/send-bulk", json={"indices": indices})
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Sent {data.get('sent', 0)} items to Organizer"

    # ── Pro Feature Check ─────────────────────────────────────

    @mcp.tool()
    async def check_pro_features() -> str:
        """Check which Burp features are available on this edition (Pro vs Community)."""
        data = await client.get("/api/burp-tools/project")
        if "error" in data:
            return f"Error: {data['error']}"

        edition_raw = (data.get("edition", "") or "").upper()
        is_pro = "PROFESSIONAL" in edition_raw
        version = data.get("burp_version", "?")

        # Feature map. Pro-only flags are flipped on COMMUNITY so Claude can
        # short-circuit before calling tools that would fail.
        features = {
            "scanner":       {"available": is_pro, "tool_examples": ["scan_url", "quick_scan", "auto_probe", "discover_attack_surface"]},
            "active_scan":   {"available": is_pro, "tool_examples": ["scan_url", "auto_probe"]},
            "passive_scan":  {"available": is_pro, "tool_examples": ["get_scanner_findings", "get_issues_dashboard"]},
            "collaborator":  {"available": is_pro, "tool_examples": ["generate_collaborator_payload", "auto_collaborator_test", "get_collaborator_interactions"]},
            "logger":        {"available": is_pro, "tool_examples": ["get_logger_entries"], "note": "Logger API may also be unavailable on older Pro builds — falls back to proxy history."},
            "crawl":         {"available": is_pro, "tool_examples": ["crawl_target", "discover_attack_surface"]},
            "repeater":      {"available": True,   "tool_examples": ["send_to_repeater", "repeater_resend"]},
            "intruder":      {"available": True,   "tool_examples": ["send_to_intruder", "send_to_intruder_configured"], "note": "Community throttles Intruder heavily — prefer fuzz_parameter via MCP."},
            "proxy":         {"available": True,   "tool_examples": ["get_proxy_history", "set_match_replace", "enable_intercept"]},
            "fuzz":          {"available": True,   "tool_examples": ["fuzz_parameter", "auto_probe", "batch_probe"]},
        }

        lines = [
            f"Burp: {version} | Edition: {edition_raw or 'UNKNOWN'} | Pro features: {'YES' if is_pro else 'NO'}",
            "",
            "Feature              Available  Tool examples",
            "-" * 88,
        ]
        for name, info in features.items():
            avail = "YES" if info["available"] else "NO"
            tools = ", ".join(info["tool_examples"][:3])
            lines.append(f"{name:<20} {avail:<10} {tools}")
            if info.get("note"):
                lines.append(f"{'':<31} note: {info['note']}")

        if not is_pro:
            lines.append("")
            lines.append("COMMUNITY EDITION — workarounds when Pro-only tools are unavailable:")
            lines.append("  - Active scan          → auto_probe + run_nuclei + run_dalfox + run_sqlmap")
            lines.append("  - Collaborator (OOB)   → use a public DNS-wildcard provider (interact.sh) and watch with poll loops")
            lines.append("  - Crawl                → browser_crawl + run_katana (both work on Community)")
            lines.append("  - Logger++             → get_proxy_history + get_mcp_history")

        return "\n".join(lines)

    # ── Intruder Config ─────────────────────────────────────────

    @mcp.tool()
    async def send_to_intruder_configured(
        index: int = -1,
        raw_request: str = "",
        host: str = "",
        tab_name: str = "MCP Attack",
        positions: list[list[int]] | None = None,
        mode: str = "",
    ) -> str:
        """Send request to Burp's Intruder with custom positions. Modes: simple, auto, or manual byte offsets.

        Args:
            index: Proxy history index (-1 to skip)
            raw_request: Raw HTTP request string (alternative to index)
            host: Target host for raw request (required with raw_request)
            tab_name: Name for the Intruder tab
            positions: List of [start, end] byte offsets for injection points
            mode: 'auto' for Burp auto-detection, '' for simple send
        """
        payload: dict = {"tab_name": tab_name}
        if index >= 0:
            payload["index"] = index
        elif raw_request and host:
            payload["raw_request"] = raw_request
            payload["host"] = host
        else:
            return "Error: provide 'index' or 'raw_request' + 'host'"

        if positions:
            payload["positions"] = positions
        if mode:
            payload["mode"] = mode

        data = await client.post("/api/burp-tools/intruder-config", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        msg = data.get("message", "")
        pos_count = data.get("positions", "")
        result = f"Sent to Intruder tab '{data.get('tab_name', tab_name)}': {data.get('method', '?')} {data.get('url', '?')}"
        if pos_count:
            result += f" ({pos_count} insertion points)"
        if data.get("mode"):
            result += f" [mode: {data['mode']}]"
        return result
