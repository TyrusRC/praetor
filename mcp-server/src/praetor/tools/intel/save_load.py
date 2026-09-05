"""save/load/coverage intel tools (split into _intel_save/_intel_load/_intel_coverage)."""

from mcp.server.fastmcp import FastMCP
from . import _intel_save, _intel_load, _intel_coverage


def register(mcp: FastMCP):
    _intel_save.register(mcp)
    _intel_load.register(mcp)
    _intel_coverage.register(mcp)
