"""Hand captured requests to Burp Repeater / Intruder."""

from mcp.server.fastmcp import FastMCP

from praetor import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_to_repeater(index: int, tab_name: str = "") -> str:
        """Send a proxy history request to Burp Repeater tab.

        Args:
            index: Proxy history index of the request
            tab_name: Optional name for the Repeater tab
        """
        payload: dict = {"index": index}
        if tab_name:
            payload["tab_name"] = tab_name

        data = await client.post("/api/http/repeater", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Repeater")

    @mcp.tool()
    async def send_to_intruder(index: int) -> str:
        """Send a proxy history request to Burp's Intruder tool for automated testing.

        Args:
            index: Proxy history index of the request
        """
        data = await client.post("/api/http/intruder", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Intruder")
