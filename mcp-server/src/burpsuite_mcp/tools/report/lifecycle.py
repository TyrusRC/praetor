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
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


async def purge_false_positives(domain: str) -> tuple[list[dict], int]:
    """Hard-delete findings whose status is in HARD_DELETE_STATUSES.

    The deletion is final: no tombstone, no audit trail, no `removed_at`
    field. Tracking dead findings just wastes tokens on every subsequent
    intel load.

    Deleting compacts survivor IDs, which changes the finding-id cited in the
    Burp proxy-history comments backing the report — so this also re-syncs those
    comments (best-effort) before persisting, same as prune / single-FP delete.

    Returns (remaining_findings, deleted_count).
    """
    path = _intel_path(domain) / "findings.json"
    if not path.exists():
        return [], 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], 0

    all_findings = data.get("findings", [])
    keep = [f for f in all_findings if f.get("status") not in HARD_DELETE_STATUSES]
    deleted = len(all_findings) - len(keep)

    if deleted > 0:
        from burpsuite_mcp.tools.notes._helpers import (
            _compact_and_remap_findings,
            resync_burp_annotations,
        )
        keep, _id_map = _compact_and_remap_findings(keep)
        await resync_burp_annotations(keep, _id_map)
        data["findings"] = keep
        data["last_modified"] = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return keep, deleted
