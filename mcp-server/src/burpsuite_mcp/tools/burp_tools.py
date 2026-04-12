"""Burp Suite native tool integrations — WebSocket send, Organizer, Decoder, Project, Logger, Intruder config."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    # ── WebSocket Send ──────────────────────────────────────────

    @mcp.tool()
    async def websocket_connect(url: str, name: str = "") -> str:
        """Open a WebSocket connection through Burp for testing WebSocket-based APIs.
        All traffic flows through Burp. Use websocket_send_message to send data.

        Args:
            url: WebSocket URL (ws:// or wss://)
            name: Connection name for reference (default: auto-generated)
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
        Use for testing WebSocket injection, authorization, and protocol abuse.

        Args:
            name: Connection name from websocket_connect
            message: Text message to send (e.g. JSON payload)
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
        """Send a proxy history item to Burp's Organizer tab for categorization.
        Use to organize interesting requests for human review.

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

    # ── Decoder ─────────────────────────────────────────────────

    @mcp.tool()
    async def send_to_decoder(data_text: str) -> str:
        """Send data to Burp's Decoder tab for manual encoding/decoding analysis.
        Opens the Decoder tab with the provided data pre-loaded.

        Args:
            data_text: Text data to send to Decoder
        """
        data = await client.post("/api/burp-tools/decoder", json={"data": data_text})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Decoder")

    # ── Project Info ────────────────────────────────────────────

    @mcp.tool()
    async def get_project_info() -> str:
        """Get current Burp Suite project info — name, ID, version, edition."""
        data = await client.get("/api/burp-tools/project")
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [
            f"Project: {data.get('project_name', '?')}",
            f"ID: {data.get('project_id', '?')}",
            f"Burp: {data.get('burp_version', '?')} ({data.get('edition', '?')})",
        ]
        return "\n".join(lines)

    # ── Logger ──────────────────────────────────────────────────

    @mcp.tool()
    async def get_logger_entries(
        limit: int = 50,
        filter_url: str = "",
    ) -> str:
        """Get Logger entries with timing data, annotations, and metadata.
        Richer than proxy history — includes color annotations and notes.

        Args:
            limit: Max entries to return (default 50)
            filter_url: Filter by URL substring
        """
        params: dict = {"limit": limit}
        if filter_url:
            params["filter_url"] = filter_url

        data = await client.get("/api/burp-tools/logger", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        items = data.get("items", [])
        if not items:
            return "No logger entries"

        lines = [f"Logger ({data.get('returned', len(items))}/{data.get('total', '?')} entries):"]
        lines.append(f"{'IDX':<6} {'METHOD':<7} {'STATUS':<7} {'SIZE':<8} {'NOTES':<20} URL")
        lines.append("-" * 90)
        for item in items:
            notes = item.get("notes", "")[:18]
            color = item.get("color", "")
            prefix = f"[{color}]" if color and color != "NONE" else ""
            lines.append(
                f"{item.get('index', '?'):<6} {item.get('method', '?'):<7} "
                f"{item.get('status_code', '?'):<7} {item.get('response_length', 0):<8} "
                f"{prefix}{notes:<20} {item.get('url', '?')[:60]}"
            )
        return "\n".join(lines)

    # ── Intruder Config ─────────────────────────────────────────

    @mcp.tool()
    async def send_to_intruder_configured(
        index: int = -1,
        raw_request: str = "",
        host: str = "",
        tab_name: str = "MCP Attack",
    ) -> str:
        """Send request to Burp's Intruder tab with a custom tab name.
        More control than send_to_intruder — lets you name the attack tab.

        Provide either index (proxy history) or raw_request + host.

        Args:
            index: Proxy history index (-1 to skip)
            raw_request: Raw HTTP request string (alternative to index)
            host: Target host for raw request (required with raw_request)
            tab_name: Name for the Intruder tab
        """
        payload: dict = {"tab_name": tab_name}
        if index >= 0:
            payload["index"] = index
        elif raw_request and host:
            payload["raw_request"] = raw_request
            payload["host"] = host
        else:
            return "Error: provide 'index' or 'raw_request' + 'host'"

        data = await client.post("/api/burp-tools/intruder-config", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Sent to Intruder tab '{data.get('tab_name', tab_name)}': {data.get('method', '?')} {data.get('url', '?')}"
