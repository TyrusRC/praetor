"""Tools for reading data from Burp Suite - proxy history, sitemap, scanner findings, scope."""

from mcp.server.fastmcp import FastMCP

from ._helpers import (
    _header_lookup, _set_cookie_values, _trim_body, _detect_error_markers,
    _slice_request_detail, _format_raw_findings,
)
from . import _history, _scope

__all__ = ["register", "_header_lookup", "_set_cookie_values", "_trim_body",
           "_detect_error_markers", "_slice_request_detail", "_format_raw_findings"]


def register(mcp: FastMCP):
    _history.register(mcp)
    _scope.register(mcp)
