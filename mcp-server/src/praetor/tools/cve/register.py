"""CVE MCP tool registrations — slim assembler.

Tool families split into per-family modules to keep each file cohesive:

- `_register_techstack` — check_tech_vulns + map_tech_to_cves
- `_register_lookup`    — lookup_cve + lookup_cpe (single CVE / list by CPE)
- `_register_search`    — search_cve (NVD-API fallback)
- `_register_kev_epss`  — kev_epss_enrich (batch KEV + EPSS sort)

Back-compat: `_shodan_cve_lookup` is re-exported at module-level so existing
tests that patch `cve.register._shodan_cve_lookup` keep working.
"""

from mcp.server.fastmcp import FastMCP

from . import (
    _register_kev_epss,
    _register_lookup,
    _register_search,
    _register_techstack,
)
from .shodan import _shodan_cve_lookup  # noqa: F401  (back-compat patch surface)


def register(mcp: FastMCP) -> None:
    _register_techstack.register(mcp)
    _register_lookup.register(mcp)
    _register_search.register(mcp)
    _register_kev_epss.register(mcp)
