"""Tools for controlling Burp proxy — intercept, match-replace, annotations, stats, traffic monitoring.

CRUD-collapsed tools:
  - intercept(action="on"|"off"|"status")
  - match_replace(action="set"|"list"|"remove"|"clear", rules=, rule_id=, force=)
  - traffic_monitor(action="register"|"check"|"remove", tag=, patterns=)
"""

from mcp.server.fastmcp import FastMCP

from ._helpers import _lookup_finding_id, _record_annotation_on_finding
from . import _config, _annotate, _stats

__all__ = ["register", "_lookup_finding_id", "_record_annotation_on_finding"]


def register(mcp: FastMCP):
    _config.register(mcp)
    _annotate.register(mcp)
    _stats.register(mcp)
