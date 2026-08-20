"""EASM + recorded-login + scan-delta + PR-comment surface.

Tools:
    recorded_login        — capture proxy indices -> create macro -> replay -> emit token
    findings_diff         — new / resolved / regression delta between two snapshots
    scope_targets_to_diff — intersect PR/git-diff changed paths with endpoints.json
    format_pr_comment     — GitHub/GitLab PR-comment markdown for a finding
    easm_monitor_loop     — subfinder + httpx + takeover sweep, persisted delta vs prior run
"""

from mcp.server.fastmcp import FastMCP

from . import findings_diff, format_pr_comment, monitor_loop, recorded_login


def register(mcp: FastMCP) -> None:
    recorded_login.register(mcp)
    findings_diff.register(mcp)
    format_pr_comment.register(mcp)
    monitor_loop.register(mcp)
