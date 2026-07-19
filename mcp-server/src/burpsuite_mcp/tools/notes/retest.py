"""record_retest — append a retest round to a finding and snapshot it immutably.

retests[] is additive to the finding record; existing readers ignore it.
Each round also writes an immutable v<N>_<date>_<status>.md snapshot and refreshes
current.md. findings.json stays the canonical source of truth.
"""
from mcp.server.fastmcp import FastMCP

from ._helpers import (
    _safe_findings_path, _load_findings_file, _write_findings_file, _find_by_id)
from ._projection import render_finding_md, write_finding_projection

_VALID = {"confirmed", "reopened", "fixed", "regressed"}


def _apply_retest(domain: str, finding_id: str, status: str, date: str,
                  evidence: str, notes: str) -> dict:
    """Append a retest round to findings.json + write the versioned snapshot.

    Returns the new retest entry. Raises ValueError on bad status, KeyError if
    the finding is absent.
    """
    if status not in _VALID:
        raise ValueError(f"status must be one of {sorted(_VALID)}")
    path = _safe_findings_path(domain)
    store = _load_findings_file(path)
    idx, finding = _find_by_id(store.get("findings", []), finding_id)
    if finding is None:
        raise KeyError(f"finding {finding_id!r} not found for {domain!r}")
    retests = finding.setdefault("retests", [])
    version = max((r.get("version", 0) for r in retests), default=0) + 1
    entry = {"version": version, "date": date, "status": status,
             "evidence": evidence, "notes": notes}
    retests.append(entry)
    finding["status"] = status
    store["findings"][idx] = finding
    _write_findings_file(path, store)
    # Import here to avoid a load-time cycle (workspace -> notes._helpers).
    from ..workspace import workspace_paths
    fdir = workspace_paths(domain)["findings"] / finding_id
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / f"v{version}_{date}_{status}.md").write_text(render_finding_md(finding))
    write_finding_projection(domain, finding)
    return entry


def register(mcp: FastMCP):
    @mcp.tool()
    async def record_retest(finding_id: str, domain: str, status: str, date: str,
                            evidence: str = "", notes: str = "") -> str:
        """Record a retest round on a finding. Writes an immutable versioned snapshot.

        Args:
            finding_id: persistent finding id (e.g. f001)
            domain: target domain
            status: confirmed | reopened | fixed | regressed
            date: YYYY-MM-DD of the retest (operator-supplied)
            evidence: optional logger_index / interaction id / note
            notes: free-text retest observation
        """
        try:
            entry = _apply_retest(domain, finding_id, status, date, evidence, notes)
        except (ValueError, KeyError) as e:
            return f"error: {e}"
        return (f"Retest v{entry['version']} recorded for {finding_id} [{status}] "
                f"— snapshot findings/{finding_id}/v{entry['version']}_{date}_{status}.md")
