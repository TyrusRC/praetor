"""Two-way Repeater tools — send to Repeater, track tabs, resend with modifications.

Unlike the basic send_to_repeater in send.py, these tools maintain a tracked map of
Repeater tabs on the Java side. This lets Claude iterate on requests: send to Repeater,
modify headers/body/path, resend, compare responses, and repeat — all without losing
track of which request is which.
"""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_to_repeater_tracked(
        index: int,
        tab_name: str = "",
    ) -> str:
        """Send a proxy history item to Burp Repeater and track it for iterative resending.

        Args:
            index: Proxy history index of the request to send
            tab_name: Optional name for the Repeater tab
        """
        payload: dict = {"index": index}
        if tab_name:
            payload["name"] = tab_name

        data = await client.post("/api/repeater/send", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"Sent to Repeater tab '{data.get('tab', '?')}'\n"
            f"  Method: {data.get('method', '?')}\n"
            f"  URL:    {data.get('url', '?')}\n"
            f"Use repeater_resend('{data.get('tab', '')}') to modify and resend."
        )

    @mcp.tool()
    async def get_repeater_tabs() -> str:
        """List all tracked Repeater tabs with their current state."""
        data = await client.get("/api/repeater/tabs")
        if "error" in data:
            return f"Error: {data['error']}"

        tabs = data.get("tabs", [])
        if not tabs:
            return "No tracked Repeater tabs. Use send_to_repeater_tracked() to create one."

        lines = [f"Tracked Repeater Tabs ({data.get('total', len(tabs))}):", ""]
        for tab in tabs:
            status = "has response" if tab.get("has_response") else "not yet sent"
            lines.append(
                f"  [{tab.get('name', '?')}] {tab.get('method', '?')} {tab.get('url', '?')}"
                f"  (sent {tab.get('send_count', 0)}x, {status})"
            )
        return "\n".join(lines)

    @mcp.tool()
    async def repeater_resend(
        tab_name: str,
        modify_headers: dict | None = None,
        modify_body: str = "",
        modify_path: str = "",
        modify_method: str = "",
    ) -> str:
        """Resend a tracked Repeater tab's request with optional modifications.

        Args:
            tab_name: Name of the tracked Repeater tab
            modify_headers: Headers to add/replace
            modify_body: New request body (replaces entire body)
            modify_path: New request path
            modify_method: New HTTP method
        """
        payload: dict = {"name": tab_name}
        if modify_headers:
            payload["modify_headers"] = modify_headers
        if modify_body:
            payload["modify_body"] = modify_body
        if modify_path:
            payload["modify_path"] = modify_path
        if modify_method:
            payload["modify_method"] = modify_method

        data = await client.post("/api/repeater/resend", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return _format_response(data)

    @mcp.tool()
    async def remove_repeater_tab(tab_name: str) -> str:
        """Remove a tracked Repeater tab from server-side tracking.

        Args:
            tab_name: Name of the tab to remove
        """
        data = await client.delete(f"/api/repeater/{tab_name}")
        if "error" in data:
            return f"Error: {data['error']}"

        return data.get("message", "Tab removed")


def _format_response(data: dict) -> str:
    """Format a Repeater resend response for LLM consumption."""
    lines = [
        f"Tab: {data.get('tab', '?')} (send #{data.get('send_count', '?')})",
        f"Status: {data.get('status_code', '?')}",
    ]

    # Response headers (compact)
    headers = data.get("response_headers", [])
    if headers:
        lines.append(f"Headers ({len(headers)}):")
        for h in headers[:20]:  # Limit to avoid token bloat
            lines.append(f"  {h.get('name', '?')}: {h.get('value', '?')}")
        if len(headers) > 20:
            lines.append(f"  ... +{len(headers) - 20} more")

    # Response body
    body = data.get("response_body", "")
    length = data.get("response_length", len(body))
    lines.append(f"Body ({length} bytes):")
    lines.append(body if body else "(empty)")

    return "\n".join(lines)
