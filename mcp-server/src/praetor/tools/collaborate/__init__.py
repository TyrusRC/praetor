"""Tools for Burp Collaborator - out-of-band testing for blind vulnerabilities."""

from mcp.server.fastmcp import FastMCP

from ._oast import (_oast_key_dir, _get_oast_fernet, _b32_dns_encode,
                    _b32_dns_decode, _pool_lock)
from . import _payloads, _oast_tools

__all__ = ["register", "_oast_key_dir", "_get_oast_fernet", "_b32_dns_encode",
           "_b32_dns_decode", "_pool_lock"]


def register(mcp: FastMCP):
    _payloads.register(mcp)
    _oast_tools.register(mcp)
