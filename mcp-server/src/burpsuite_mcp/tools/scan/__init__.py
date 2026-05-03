"""Adaptive scan engine — discover attack surface and auto-probe.

Split into submodules for maintainability. The original `scan.py` (1225 LOC)
exported a single `register(mcp)`; that public surface is preserved here.

Submodules:
- _constants    — PARAM_RISK_MAP, COMMON/EXTENDED_PARAMS, REFERENCE_ONLY, KNOWLEDGE_DIR
- _helpers      — _load_knowledge / _load_all_knowledge / _classify_param_risk / _compact_targets
- discovery     — discover_attack_surface, discover_hidden_parameters
- auto_probe    — auto_probe (knowledge-driven)
- quick_probes  — quick_scan, probe_endpoint, batch_probe
- recon_full    — full_recon (multi-step pipeline)
- bulk          — bulk_test (one vuln class × N endpoints)
"""

from mcp.server.fastmcp import FastMCP

# Re-export module-private symbols so external imports (advisor.py, intel.py,
# tests) keep working unchanged.
from ._constants import (  # noqa: F401
    KNOWLEDGE_DIR,
    _COMMON_PARAMS,
    _EXTENDED_PARAMS,
    _PARAM_RISK_MAP,
    _REFERENCE_ONLY,
)
from ._helpers import (  # noqa: F401
    _classify_param_risk,
    _compact_targets,
    _load_all_knowledge,
    _load_knowledge,
    _matches_param,
)
from . import auto_probe as _auto_probe
from . import bulk as _bulk
from . import discovery as _discovery
from . import quick_probes as _quick_probes
from . import recon_full as _recon_full


def register(mcp: FastMCP) -> None:
    """Register all scan-engine MCP tools."""
    _discovery.register(mcp)
    _auto_probe.register(mcp)
    _quick_probes.register(mcp)
    _recon_full.register(mcp)
    _bulk.register(mcp)
