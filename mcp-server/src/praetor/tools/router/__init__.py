"""Signal->tool router: makes existing tools fire on matching signals under a
Balanced policy. Single tool: route_signals."""

from mcp.server.fastmcp import FastMCP

from . import route


def register(mcp: FastMCP) -> None:
    route.register(mcp)
