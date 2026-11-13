"""burp-expedition lane — MCP tools for the non-HTTP TCP/UDP proxy extension."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import evidence_tools, protocol_probes, scripting_dns, tools


def register(mcp: FastMCP) -> None:
    tools.register(mcp)
    protocol_probes.register(mcp)
    evidence_tools.register(mcp)
    scripting_dns.register(mcp)


__all__ = ["register"]
