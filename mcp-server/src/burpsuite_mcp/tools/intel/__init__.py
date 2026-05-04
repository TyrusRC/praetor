"""Persistent target intelligence — split from a single 925-line intel.py.

Public surface preserved:
- register(mcp) — wires every intel @mcp.tool() onto the server.
- _intel_path / _intel_root / _ensure_dir — used by save_finding,
  auto_probe, advisor for path resolution.
- _atomic_write_json — used by notes.py and the advisor for safe writes.
- _knowledge_version — auto_probe coverage stamping.
- recon_gate_check — Rule 20a entry point.
- _empty_structure / _finding_vuln_type / _deduplicate_finding — used
  internally and by tests/tools that compose findings.
- INTEL_DIR — legacy attribute proxied through __getattr__.
- load_active_program_policy — read-only helper for advisor.assess.
- KNOWLEDGE_DIR — same path as before (one level up from this package).
"""

from mcp.server.fastmcp import FastMCP

from . import (
    cross_target,
    freshness,
    header_profile,
    program_policy,
    save_load,
)
from ._internals import (
    KNOWLEDGE_DIR,
    VALID_CATEGORIES,
    _atomic_write_json,
    _deduplicate_finding,
    _empty_structure,
    _ensure_dir,
    _finding_vuln_type,
    _intel_path,
    _intel_root,
    _knowledge_version,
    recon_gate_check,
)
from .program_policy import load_active_program_policy


def __getattr__(name: str):
    """Backwards-compat shim — older callers read intel.INTEL_DIR directly."""
    if name == "INTEL_DIR":
        return _intel_root()
    raise AttributeError(name)


def register(mcp: FastMCP) -> None:
    save_load.register(mcp)
    freshness.register(mcp)
    cross_target.register(mcp)
    header_profile.register(mcp)
    program_policy.register(mcp)


__all__ = [
    "register",
    "KNOWLEDGE_DIR",
    "VALID_CATEGORIES",
    "_atomic_write_json",
    "_deduplicate_finding",
    "_empty_structure",
    "_ensure_dir",
    "_finding_vuln_type",
    "_intel_path",
    "_intel_root",
    "_knowledge_version",
    "recon_gate_check",
    "load_active_program_policy",
]
