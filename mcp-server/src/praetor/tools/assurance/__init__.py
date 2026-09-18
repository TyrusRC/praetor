"""Assurance & reporting layer: standards coverage, posture dashboard, compliance.

Sits above the testing engine — answers "what did we test vs the standard",
"what's our posture", "how do findings map to a compliance framework". All
pure-function + JSON-load; no Burp client, no network.
"""

from mcp.server.fastmcp import FastMCP

from . import asset_matrix, coverage_map, dashboard, compliance, _checklists


def register(mcp: FastMCP) -> None:
    coverage_map.register(mcp)
    asset_matrix.register(mcp)
    _checklists.register(mcp)
    dashboard.register(mcp)
    compliance.register(mcp)
