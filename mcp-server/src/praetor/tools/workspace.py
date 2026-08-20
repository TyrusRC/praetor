"""Engagement workspace layout — single source of per-domain artifact paths.

Machine files (profile.json, findings.json, ...) stay at the domain root.
This module owns the human-facing subdir tree only.
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_SUBDIRS = {
    "findings": ("findings",),
    "artifacts": ("artifacts",),
    "screenshots": ("artifacts", "screenshots"),
    "captures": ("artifacts", "captures"),
    "poc": ("artifacts", "poc"),
    "testcases": ("testcases",),
    "reports": ("reports",),
    "material": ("material",),
    "wordlists": ("material", "wordlists"),
    "tool_output": ("material", "tool-output"),
    # Network / red-team lane — evidence that never routes through Burp
    # (nmap/impacket/responder run records) and captured secrets.
    "network": ("network",),
    "loot": ("network", "loot"),
}


def workspace_paths(domain: str) -> dict[str, Path]:
    """Return every workspace subdir path for a domain. Single source of truth.

    Raises ValueError on path-traversal input (delegated to _sanitized).
    """
    # Local import: keeps module load free of a notes<->workspace import cycle.
    from praetor.tools.notes._helpers import _intel_dir, _sanitized
    root = _intel_dir() / _sanitized(domain)
    paths: dict[str, Path] = {"root": root}
    for key, parts in _SUBDIRS.items():
        paths[key] = root.joinpath(*parts)
    return paths


def ensure_workspace(domain: str) -> dict[str, Path]:
    """Idempotently create the full workspace tree. Returns workspace_paths(domain)."""
    paths = workspace_paths(domain)
    for key, path in paths.items():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def register(mcp: FastMCP):
    @mcp.tool()
    async def scaffold_workspace(domain: str) -> str:
        """Create the engagement workspace tree for a domain.

        Layout: findings/ artifacts/{screenshots,captures,poc}/ testcases/ reports/
        material/{wordlists,tool-output}/. Machine files (findings.json, profile.json,
        ...) stay at the domain root.

        Directories only. The tree previously shipped a one-line README in each
        subdirectory, which made placeholder files half of everything in a fresh
        workspace and buried the real artefacts — the layout is documented in
        CLAUDE.md, where it is actually read.
        """
        paths = ensure_workspace(domain)
        return (
            f"Workspace ready at {paths['root']}\n"
            "  findings/  artifacts/{screenshots,captures,poc}/  testcases/  "
            "reports/  material/{wordlists,tool-output}/"
        )
