"""Offline artifact analysis — Burp-independent recon of raw requests, JS, and
project trees. Single tool: analyze_artifact."""

from mcp.server.fastmcp import FastMCP

from . import entry


def register(mcp: FastMCP) -> None:
    entry.register(mcp)
