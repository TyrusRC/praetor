"""Write-side notes tools: save_finding, hydrate_burp_findings,
mark_finding_false_positive, prune_findings. Mutates findings.json and the Burp
in-memory store.

Split by responsibility:
  _finding.py     - save_finding (+ the systemic-sibling gate helper)
  _hydrate.py     - hydrate_burp_findings
  _maintenance.py - mark_finding_false_positive, prune_findings
"""

from mcp.server.fastmcp import FastMCP

# Re-exported so `praetor.tools.notes.save.client` stays a valid patch target
# (the test suite patches notes.save.client.post).
from praetor import client  # noqa: F401

from . import _finding, _hydrate, _maintenance
from ._systemic import _find_systemic_sibling  # noqa: F401


def register(mcp: FastMCP):
    _finding.register(mcp)
    _hydrate.register(mcp)
    _maintenance.register(mcp)


__all__ = ["register"]
