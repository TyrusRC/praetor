"""Red-team knowledge, operator-log evidence, and Ghostwriter forwarding.

  lookup_gtfobins / lookup_lolbas / redteam_tool_guide  - knowledge (lookup.py)
  record_redteam_action / record_loot / get_operator_log - evidence (oplog_tools.py)
  sync_to_ghostwriter / ghostwriter_status               - central hub (ghostwriter_tools.py)

The web lane cites Burp logger_index; this lane cites operator-log ids. Both
forward into Ghostwriter as the single reporting/oplog centre for the engagement.
"""

from mcp.server.fastmcp import FastMCP

from . import ghostwriter_tools, lookup, oplog_tools, postex


def register(mcp: FastMCP) -> None:
    lookup.register(mcp)
    oplog_tools.register(mcp)
    ghostwriter_tools.register(mcp)
    postex.register(mcp)


__all__ = ["register"]
