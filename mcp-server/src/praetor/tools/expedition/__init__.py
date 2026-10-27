"""burp-expedition lane — MCP tools for the non-HTTP TCP/UDP proxy extension."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import tools, protocol_probes


def register(mcp: FastMCP) -> None:
    tools.register(mcp)
    protocol_probes.register(mcp)


__all__ = ["register"]
