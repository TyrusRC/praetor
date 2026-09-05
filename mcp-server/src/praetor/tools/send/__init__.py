"""Tools for sending HTTP requests through Burp Suite.

Requests are routed through Burp's proxy listener (ProxyTunnel) so they appear
in **Proxy → HTTP history** AND the **Logger** tab AND the MCP history store
(get_mcp_history). Anomalies are auto-highlighted on the Proxy entry. If the
proxy listener is unreachable, the extension falls back to the direct HTTP
client and only Logger sees the request.
"""

from mcp.server.fastmcp import FastMCP

from ._format import _format_curl_response, _format_response, _truncate_body
from . import _send, _concurrent, _burp_ui

__all__ = ["register", "_format_curl_response", "_format_response", "_truncate_body"]


def register(mcp: FastMCP):
    _send.register(mcp)
    _burp_ui.register(mcp)
    _concurrent.register(mcp)
