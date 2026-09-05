"""Evidence-flow curation: curate_evidence + audit_history_noise."""

from mcp.server.fastmcp import FastMCP

from . import tools


def register(mcp: FastMCP) -> None:
    tools.register(mcp)
