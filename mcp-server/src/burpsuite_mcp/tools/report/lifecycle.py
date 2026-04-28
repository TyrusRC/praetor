"""Findings lifecycle: load + hard-delete false positives. No tombstones."""

import json
from datetime import datetime, timezone

from burpsuite_mcp.tools.intel import _intel_path

# Reportable status values. Anything NOT in this set is excluded from reports
# and (for `likely_false_positive`) is hard-deleted before generation runs.
REPORTABLE_STATUSES = {"confirmed"}
HARD_DELETE_STATUSES = {"likely_false_positive"}


def load_intel(domain: str, category: str) -> dict:
    """Load intel data for a domain."""
    path = _intel_path(domain) / f"{category}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def purge_false_positives(domain: str) -> tuple[list[dict], int]:
    """Hard-delete findings whose status is in HARD_DELETE_STATUSES.

    The deletion is final: no tombstone, no audit trail, no `removed_at`
    field. Tracking dead findings just wastes tokens on every subsequent
    intel load.

    Returns (remaining_findings, deleted_count).
    """
    path = _intel_path(domain) / "findings.json"
    if not path.exists():
        return [], 0
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return [], 0

    all_findings = data.get("findings", [])
    keep = [f for f in all_findings if f.get("status") not in HARD_DELETE_STATUSES]
    deleted = len(all_findings) - len(keep)

    if deleted > 0:
        data["findings"] = keep
        data["last_modified"] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(data, indent=2))

    return keep, deleted
