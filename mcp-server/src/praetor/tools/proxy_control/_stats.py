"""Proxy traffic: stats, live requests, pattern monitor."""

from mcp.server.fastmcp import FastMCP

import json

from praetor import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_proxy_stats() -> str:
        """Get proxy traffic statistics -- total requests, unique hosts, method and status distributions."""
        data = await client.get("/api/traffic/stats")
        if "error" in data:
            return f"Error: {data['error']}"
        lines = [f"Proxy Stats ({data.get('total_requests', 0)} total requests)"]
        lines.append(f"  Unique hosts: {data.get('unique_hosts', 0)}")
        methods = data.get("method_distribution", {})
        if methods:
            lines.append(f"\n  Methods: {', '.join(f'{k}={v}' for k, v in methods.items())}")
        statuses = data.get("status_code_distribution", {})
        if statuses:
            lines.append(f"  Status codes: {', '.join(f'{k}={v}' for k, v in statuses.items())}")
        return "\n".join(lines)

    @mcp.tool()
    async def get_live_requests(since_index: int) -> str:
        """Get new proxy requests captured since a given index.

        Args:
            since_index: Return items after this proxy history index
        """
        data = await client.get("/api/traffic/live", params={"since_index": since_index})
        if "error" in data:
            return f"Error: {data['error']}"
        items = data.get("items", [])
        if not items:
            return f"No new requests since #{since_index}"
        lines = [f"New Requests ({len(items)} since #{since_index}):"]
        lines.append(f"{'IDX':<7} {'METHOD':<8} {'STATUS':<7} URL")
        lines.append("-" * 80)
        for item in items:
            lines.append(
                f"{item.get('index', '?'):<7} {item.get('method', '?'):<8} "
                f"{item.get('status_code', '?'):<7} {item.get('url', '?')}"
            )
        return "\n".join(lines)

    # ── Traffic Monitoring (collapsed) ──────────────────────────

    @mcp.tool()
    async def traffic_monitor(
        action: str = "check",
        tag: str = "",
        patterns: list[dict] | None = None,
    ) -> str:
        """Register and check regex-based traffic monitors over proxy traffic.

        Args:
            action: 'register' (create monitor), 'check' (get hits), 'remove' (delete)
            tag: Monitor name (required for all actions)
            patterns: For action=register — list of {location, regex} dicts
        """
        a = action.lower()
        if not tag:
            return "Error: tag is required"

        if a == "register":
            if not patterns:
                return "Error: action=register requires patterns list"
            data = await client.post("/api/traffic/monitor/register", json={
                "tag": tag, "patterns": patterns,
            })
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Monitor '{tag}' registered with {len(patterns)} pattern(s). Use traffic_monitor(action='check', tag='{tag}') to check for hits."

        if a == "check":
            data = await client.get("/api/traffic/monitor/check", params={"tag": tag})
            if "error" in data:
                return f"Error: {data['error']}"
            hits = data.get("hits", [])
            if not hits:
                return f"Monitor '{tag}': no new hits"
            lines = [f"Monitor '{tag}' — {len(hits)} hit(s):"]
            for hit in hits:
                lines.append(
                    f"  [#{hit.get('index')}] {str(hit.get('matched_text', ''))[:100]}"
                )
            return "\n".join(lines)

        if a == "remove":
            data = await client.delete(f"/api/traffic/monitor/{tag}")
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Monitor '{tag}' removed"

        return f"Unknown action '{action}'. Use 'register', 'check', or 'remove'."
