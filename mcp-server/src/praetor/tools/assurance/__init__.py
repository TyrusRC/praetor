"""Assurance & reporting layer: standards coverage, posture dashboard, compliance.

Sits above the testing engine — answers "what did we test vs the standard",
"what's our posture", "how do findings map to a compliance framework". All
pure-function + JSON-load; no Burp client, no network.
"""

from mcp.server.fastmcp import FastMCP

from . import coverage_map, dashboard, compliance


def register(mcp: FastMCP) -> None:
    coverage_map.register(mcp)
    dashboard.register(mcp)
    compliance.register(mcp)
