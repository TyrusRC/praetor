"""Coverage + test-journal recording for confirm_*/escalate_* exploit tools.

auto_probe records coverage via scan/_impl.record_coverage(). The exploit
tools bypass auto_probe, so without this helper the coverage heatmap and
checklist system never learn that a class was tested via a targeted tool.

Call record_exploit_coverage() before returning a CONFIRMED or FAILED verdict.
INCONCLUSIVE and ERROR verdicts do NOT count as coverage (Rule 19a).

Every decisive call also writes a structured entry to test_journal.jsonl —
the single file the operator reads to answer "which tests ran, on what, and
what happened?" (coverage.json answers "was it tested?" but not the result).

Outcome taxonomy (5 states, inspired by ARTEX coverage_ledger):
  vulnerable       — confirmed vulnerability, finding saved
  clean            — tested, no issue found (evidence_ref required)
  ruled_out        — structurally impossible for this stack (reason required)
  not_applicable   — not relevant for this endpoint (reason required)
  needs_follow_up  — partially tested, blocked, or inconclusive
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── 5-outcome coverage taxonomy ─────────────────────────────────────────────
COVERAGE_OUTCOMES: dict[str, str] = {
    "vulnerable": "Confirmed vulnerability — finding saved",
    "clean": "Tested, no issue found — evidence ref required",
    "ruled_out": "Structurally impossible for this stack — reason required",
    "not_applicable": "Not relevant for this endpoint — reason required",
    "needs_follow_up": "Partially tested, blocked or inconclusive",
}


def _verdict_to_outcome(verdict: str) -> str:
    """Map a legacy verdict string to the canonical outcome."""
    v = (verdict or "").strip().lower()
    if v in COVERAGE_OUTCOMES:
        return v
    if v in ("confirmed", "vulnerable"):
        return "vulnerable"
    if v in ("failed", "clean", "not_vulnerable", "not vulnerable"):
        return "clean"
    if v in ("ruled_out", "n/a", "not_applicable"):
        return "ruled_out"
    return "needs_follow_up"


def record_exploit_coverage(
    domain: str,
    endpoint: str,
    parameter: str,
    vuln_class: str,
    verdict: str = "",
    tool_name: str = "",
    proxy_index: int = -1,
    outcome: str = "",
    evidence_ref: str = "",
    reason: str = "",
) -> None:
    """Record coverage + test-journal entry for a confirmed/failed exploit test.

    Best-effort — failure never breaks the tool's response.

    Args:
        outcome: One of COVERAGE_OUTCOMES keys. When empty, derived from verdict
                 for backward compatibility.
        evidence_ref: Proxy-history index or journal entry ID. Required when
                      outcome is "clean" — logged as warning if missing.
        reason: Explanation string. Required when outcome is "ruled_out" or
                "not_applicable" — logged as warning if missing.
    """
    if not domain or not endpoint or not vuln_class:
        return
    try:
        from praetor.tools.intel import _knowledge_version, _intel_path

        base = _intel_path(domain)
        base.mkdir(parents=True, exist_ok=True)
        kv = _knowledge_version()
        ts = datetime.now(timezone.utc).isoformat()

        resolved_outcome = outcome if outcome in COVERAGE_OUTCOMES else _verdict_to_outcome(verdict)

        if resolved_outcome == "clean" and not evidence_ref:
            logger.warning(
                "coverage outcome 'clean' without evidence_ref for %s %s %s",
                endpoint, vuln_class, parameter,
            )
        if resolved_outcome in ("ruled_out", "not_applicable") and not reason:
            logger.warning(
                "coverage outcome '%s' without reason for %s %s %s",
                resolved_outcome, endpoint, vuln_class, parameter,
            )

        # --- coverage.json (tested-tuple heatmap) ---
        cov_path = base / "coverage.json"
        cov: dict = {"entries": []}
        if cov_path.exists():
            try:
                cov = json.loads(cov_path.read_text(encoding="utf-8")) or {"entries": []}
            except (OSError, json.JSONDecodeError):
                cov = {"entries": []}
        if "entries" not in cov or not isinstance(cov["entries"], list):
            cov["entries"] = []

        key = (endpoint, parameter or "", vuln_class)
        found = False
        for e in cov["entries"]:
            if (e.get("endpoint"), e.get("parameter"), e.get("category")) == key:
                e["knowledge_version"] = kv
                e["verdict"] = verdict or e.get("verdict", "")
                e["outcome"] = resolved_outcome
                e["tested_at"] = ts
                if evidence_ref:
                    e["evidence_ref"] = evidence_ref
                if reason:
                    e["reason"] = reason
                found = True
                break
        if not found:
            entry_dict: dict = {
                "endpoint": endpoint,
                "parameter": parameter or "",
                "category": vuln_class,
                "knowledge_version": kv,
                "source": "exploit_tool",
                "verdict": verdict,
                "outcome": resolved_outcome,
                "tested_at": ts,
            }
            if evidence_ref:
                entry_dict["evidence_ref"] = evidence_ref
            if reason:
                entry_dict["reason"] = reason
            cov["entries"].append(entry_dict)
        cov_path.write_text(
            json.dumps(cov, separators=(",", ":")), encoding="utf-8"
        )

        # --- test_journal.jsonl (structured test log) ---
        journal_path = base / "test_journal.jsonl"
        journal_entry = {
            "ts": ts,
            "endpoint": endpoint,
            "parameter": parameter or "",
            "vuln_class": vuln_class,
            "verdict": verdict,
            "outcome": resolved_outcome,
            "tool": tool_name,
            "proxy_index": proxy_index if proxy_index >= 0 else None,
        }
        if evidence_ref:
            journal_entry["evidence_ref"] = evidence_ref
        if reason:
            journal_entry["reason"] = reason
        with journal_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(journal_entry, separators=(",", ":")) + "\n")

    except Exception:
        pass


# ── coverage gap analysis ────────────────────────────────────────────────────

def _load_coverage_entries(domain: str) -> list[dict]:
    """Load coverage.json entries for a domain. Returns [] on any error."""
    try:
        from praetor.tools.intel import _intel_path
        cov_path = _intel_path(domain) / "coverage.json"
        if not cov_path.exists():
            return []
        cov = json.loads(cov_path.read_text(encoding="utf-8"))
        entries = cov.get("entries", [])
        return entries if isinstance(entries, list) else []
    except Exception:
        return []


def _all_active_kb_categories() -> list[str]:
    """Return sorted list of active (non-reference-only) KB category names."""
    try:
        from praetor.tools.scan._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY
        return sorted(
            f.stem for f in KNOWLEDGE_DIR.glob("*.json")
            if f.stem not in _REFERENCE_ONLY
        )
    except Exception:
        return []


def coverage_gaps(domain: str) -> dict:
    """Compute coverage gap analysis for a domain.

    Returns:
        dict with keys:
          by_outcome   — {outcome: count} totals
          follow_ups   — entries where outcome is needs_follow_up
          uncovered     — KB categories with zero coverage entries
          summary       — compact multi-line string for agent prompt
    """
    entries = _load_coverage_entries(domain)
    all_cats = _all_active_kb_categories()

    by_outcome: dict[str, int] = {k: 0 for k in COVERAGE_OUTCOMES}
    covered_cats: set[str] = set()
    follow_ups: list[dict] = []

    for e in entries:
        outcome = e.get("outcome") or _verdict_to_outcome(e.get("verdict", ""))
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        covered_cats.add(e.get("category", ""))
        if outcome == "needs_follow_up":
            follow_ups.append({
                "endpoint": e.get("endpoint", ""),
                "parameter": e.get("parameter", ""),
                "category": e.get("category", ""),
            })

    uncovered = sorted(c for c in all_cats if c not in covered_cats)

    total = sum(by_outcome.values())
    lines = [f"Coverage for {domain}: {total} entries"]
    for outcome, count in by_outcome.items():
        if count:
            lines.append(f"  {outcome}: {count}")
    if follow_ups:
        lines.append(f"  open follow-ups: {len(follow_ups)}")
    if uncovered:
        shown = uncovered[:10]
        lines.append(f"  uncovered categories ({len(uncovered)}): {', '.join(shown)}"
                     + (" ..." if len(uncovered) > 10 else ""))

    return {
        "by_outcome": by_outcome,
        "follow_ups": follow_ups,
        "uncovered": uncovered,
        "summary": "\n".join(lines),
    }
