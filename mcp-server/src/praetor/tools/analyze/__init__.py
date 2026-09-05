"""Analysis tools: parameters, tech stack, JS secrets, DOM, smart-analyze."""

from mcp.server.fastmcp import FastMCP

from ._helpers import _score_security_headers
from . import _extract, _smart

__all__ = ["register", "_score_security_headers"]


def register(mcp: FastMCP):
    _extract.register(mcp)
    _smart.register(mcp)
