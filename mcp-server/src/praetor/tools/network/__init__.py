"""Network / red-team lane: recon + AD/post-ex tools that bypass Burp.

Evidence lands in the operator log (network/oplog.jsonl, ATT&CK-tagged), not a
Burp logger_index. Tools: run_nmap, get_network_inventory, run_network_tool,
run_network_recon. HARD safety (Rules 5-9) and mode-aware scope (Rule 1) apply.
"""

from mcp.server.fastmcp import FastMCP

from . import nmap, pipeline, run_tool


def register(mcp: FastMCP) -> None:
    nmap.register(mcp)
    run_tool.register(mcp)
    pipeline.register(mcp)


__all__ = ["register"]
