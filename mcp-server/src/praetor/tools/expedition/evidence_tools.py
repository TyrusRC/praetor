"""MCP tools for expedition evidence management — tag, search, session save/load.

Closes the gap where praetor cannot annotate, search, or export expedition
captures the way it does for HTTP proxy history.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def tcp_annotate(
        connection_id: int,
        color: str = "",
        comment: str = "",
    ) -> str:
        """Tag an expedition connection with a color and/or comment (evidence annotation).

        The non-HTTP equivalent of annotate_request. Tags persist for the
        session and appear in tcp_proxy_connections output and session exports.

        Args:
            connection_id: Expedition connection ID to tag.
            color: Color tag (RED/ORANGE/YELLOW/GREEN/CYAN/BLUE/PINK/GRAY).
            comment: Free-text comment (finding ID, vuln class, evidence note).
        """
        if not color and not comment:
            return "Error: provide color or comment (or both)."
        d = await _client.post(f"/connections/{connection_id}/tag", json={
            "color": color, "comment": comment,
        })
        if "error" in d:
            return f"Error: {d['error']}"
        tags = d.get("tags", [])
        return f"Tagged connection #{connection_id}: {tags}"

    @mcp.tool()
    async def tcp_search(
        query: str,
        limit: int = 50,
    ) -> str:
        """Search expedition message content by text (like search_history for HTTP).

        Searches the ASCII preview of all captured TCP/UDP messages for a
        substring match. Returns matching messages with connection IDs.

        Args:
            query: Text to search for in message content.
            limit: Max results (default 50).
        """
        if not query.strip():
            return "Error: empty query."
        d = await _client.get_list(f"/messages/search?q={query}&limit={limit}")
        if isinstance(d, dict) and "error" in d:
            return f"Error: {d['error']}"
        if not d:
            return f"No messages matching '{query}'."
        rows = d if isinstance(d, list) else []
        lines = [f"{len(rows)} message(s) matching '{query}':"]
        for m in rows[:20]:
            arrow = "C->U" if m.get("direction") == "CLIENT_TO_UPSTREAM" else "U->C"
            lines.append(
                f"  msg#{m.get('id')} conn#{m.get('connection_id')} {arrow} "
                f"{m.get('length')}B  {str(m.get('text', ''))[:80]!r}"
            )
        if len(rows) > 20:
            lines.append(f"  ... ({len(rows) - 20} more)")
        return "\n".join(lines)

    @mcp.tool()
    async def tcp_session_save(path: str = "") -> str:
        """Save the current expedition session (connections, messages, tags) to a JSON file.

        Preserves the full capture for evidence. Load it later with tcp_session_load.

        Args:
            path: File path to save to (default: expedition-session.json in cwd).
        """
        d = await _client.post("/session/save", json={"path": path or ""})
        if "error" in d:
            return f"Error: {d['error']}"
        return (
            f"Session saved to {d.get('path')}: "
            f"{d.get('connections')} connections, "
            f"{d.get('messages')} messages, "
            f"{d.get('tags')} tags."
        )

    @mcp.tool()
    async def tcp_session_load(path: str) -> str:
        """Load a saved expedition session from a JSON file.

        Restores connections, messages, and tags from a prior save.

        Args:
            path: File path to load from.
        """
        if not path.strip():
            return "Error: path required."
        d = await _client.post("/session/load", json={"path": path})
        if "error" in d:
            return f"Error: {d['error']}"
        return (
            f"Session loaded from {path}: "
            f"{d.get('connections')} connections, "
            f"{d.get('messages')} messages, "
            f"{d.get('tags')} tags."
        )
