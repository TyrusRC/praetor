"""Vulnerability scanners: nuclei, dalfox, commix, sqlmap, nikto, wpscan, ysoserial."""

from mcp.server.fastmcp import FastMCP
from . import _g1, _g2


def register(mcp: FastMCP):
    _g1.register(mcp)
    _g2.register(mcp)


# Re-export _shared surface for package-path patches/access.
from . import _shared as _shared  # noqa: E402
globals().update({_k: getattr(_shared, _k) for _k in dir(_shared) if not _k.startswith("__")})
