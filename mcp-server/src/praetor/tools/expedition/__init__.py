"""burp-expedition lane — MCP tools for the non-HTTP TCP/UDP proxy extension."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import tools, protocol_probes, evidence_tools


def register(mcp: FastMCP) -> None:
    tools.register(mcp)
    protocol_probes.register(mcp)
    evidence_tools.register(mcp)


__all__ = ["register"]
