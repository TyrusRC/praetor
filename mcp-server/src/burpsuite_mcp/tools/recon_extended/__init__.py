"""Python-only external recon — CT logs, Wayback, DNS, subdomain takeover.

Package split from a 510-LOC single file for navigability. `test_rate_limit`
lives in `tools/testing/rate_limit.py` — it is a behavior probe, not recon.

Back-compat re-exports keep `from burpsuite_mcp.tools.recon_extended import
TAKEOVER_FINGERPRINTS` and `recon_extended.register(mcp)` working.
"""

from mcp.server.fastmcp import FastMCP

from . import crtsh, dns_analysis, takeover, wayback
from ._common import _dig, _dig_available, _sanitize_domain
from .fingerprints import TAKEOVER_FINGERPRINTS

__all__ = [
    "TAKEOVER_FINGERPRINTS",
    "_sanitize_domain",
    "_dig",
    "_dig_available",
    "register",
]


def register(mcp: FastMCP) -> None:
    crtsh.register(mcp)
    wayback.register(mcp)
    dns_analysis.register(mcp)
    takeover.register(mcp)
