"""Detailed per-test-case checklists for the OWASP standards.

`_standards.py` tracks coverage at the CATEGORY level (what did we NOT test).
This package adds test-case granularity: every individual test in a guide, its
parent category, and the Praetor tool/approach that runs it — so a checklist can
be walked item by item and each confirmed.

Split by concern: `_catalogs` (the static AI/WSTG/MASTG data + assembly),
`_status` (per-item persistence, render, run-plan ordering, verdict mapping),
`_tools` (the MCP tool surface). Public API is re-exported here unchanged.
"""

from __future__ import annotations

from ._catalogs import CHECKLISTS, checklist_for
from ._status import (
    next_open_items,
    render_checklist,
    verdict_to_checklist_status,
)
from ._tools import register

__all__ = [
    "CHECKLISTS",
    "checklist_for",
    "next_open_items",
    "render_checklist",
    "verdict_to_checklist_status",
    "register",
]
