"""notes/ — save / query / export pentest findings.

Split from a single 681-line notes.py:

    _helpers.py — path resolution, atomic file I/O, dedup, FP delete
    save.py     — save_finding, hydrate_burp_findings, mark_finding_false_positive
    query.py    — get_findings, export_report

The top-level `register(mcp)` keeps the existing call site in server.py
(`notes.register(mcp)`) working unchanged. Helpers are re-exported so external
test code that imported `from burpsuite_mcp.tools.notes import _dedupe_finding`
keeps resolving.
"""

from mcp.server.fastmcp import FastMCP

from . import export_junit, export_sarif, query, repro_script, save
from ._helpers import (
    _dedupe_finding,
    _domain_from_endpoint,
    _find_by_id,
    _format_proof_for_review,
    _hard_delete_finding,
    _intel_dir,
    _load_findings_file,
    _safe_findings_path,
    _sanitized,
    _write_findings_file,
)

__all__ = [
    "register",
    "_dedupe_finding",
    "_domain_from_endpoint",
    "_find_by_id",
    "_format_proof_for_review",
    "_hard_delete_finding",
    "_intel_dir",
    "_load_findings_file",
    "_safe_findings_path",
    "_sanitized",
    "_write_findings_file",
]


def register(mcp: FastMCP):
    save.register(mcp)
    query.register(mcp)
    export_sarif.register(mcp)
    export_junit.register(mcp)
    repro_script.register(mcp)
