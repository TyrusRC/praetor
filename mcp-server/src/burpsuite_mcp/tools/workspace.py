"""Engagement workspace layout — single source of per-domain artifact paths.

Machine files (profile.json, findings.json, ...) stay at the domain root.
This module owns the human-facing subdir tree only. See Spec 1:
docs/superpowers/specs/2026-07-19-engagement-workspace-foundation-design.md
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized

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
}


def workspace_paths(domain: str) -> dict[str, Path]:
    """Return every workspace subdir path for a domain. Single source of truth.

    Raises ValueError on path-traversal input (delegated to _sanitized).
    """
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
        """Create the engagement workspace tree for a domain and drop a README in each subdir.

        Layout: findings/ artifacts/{screenshots,captures,poc}/ testcases/ reports/
        material/{wordlists,tool-output}/. Machine files (findings.json, profile.json,
        ...) stay at the domain root.
        """
        paths = ensure_workspace(domain)
        readmes = {
            "screenshots": "PNG evidence referenced by findings.",
            "captures": "Saved request/response pairs.",
            "poc": "PoC scripts and exported bundles.",
            "testcases": "Testcase-status matrices (WSTG / API Top 10 / custom).",
            "reports": "Imported report templates and generated reports.",
            "wordlists": "Wordlists used against this target.",
            "tool_output": "Raw external-tool output (ffuf/nuclei/etc.).",
        }
        for key, text in readmes.items():
            readme = paths[key] / "README.md"
            if not readme.exists():
                readme.write_text(f"# {key}\n\n{text}\n")
        return f"Workspace ready at {paths['root']}"
