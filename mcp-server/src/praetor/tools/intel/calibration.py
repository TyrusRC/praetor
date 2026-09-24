"""Confidence-calibration ledger — persist (predicted confidence → real outcome)
pairs and report how well verdict confidences match reality.

RLCD-inspired (see testing/_calibration.py). Ground truth is only known at two
moments, so the ledger is written from exactly those hooks:
  - record_retest(status=confirmed|regressed|reopened|fixed) → true_positive
  - mark_finding_false_positive(...)                          → false_positive
plus an operator-facing tool for external ground truth (a triager accept/reject).

Calibration is a property of the probe CLASS, not the target, so the ledger is
GLOBAL: ~/.praetor/calibration/ledger.jsonl (the ~/.praetor convention used by
mcptox / benchmarks). Append-only JSONL; a write failure never propagates to the
caller — a lost calibration point must not break a deletion or a retest.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools._calibration import calibration_summary, outcome_label


def _ledger_path() -> Path:
    return Path.home() / ".praetor" / "calibration" / "ledger.jsonl"


def record_calibration(
    vuln_type: str,
    confidence: float,
    outcome: str,
    *,
    verdict: str = "",
    source: str = "",
    domain: str = "",
) -> bool:
    """Append one (confidence → outcome) pair to the global ledger.

    Returns True on write, False on any failure (caller ignores the result —
    this is best-effort instrumentation, never a hard dependency). Records with
    an unrecognised outcome are still stored (so a later mapping change can score
    them); scoring drops them at read time.
    """
    try:
        conf = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        return False
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "vuln_type": (vuln_type or "").strip().lower() or "unknown",
        "confidence": round(conf, 3),
        "outcome": (outcome or "").strip().lower(),
        "verdict": verdict,
        "source": source,
        "domain": domain,
    }
    try:
        path = _ledger_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return True
    except OSError:
        return False


def _load_ledger(vuln_type: str = "") -> list[dict]:
    path = _ledger_path()
    if not path.exists():
        return []
    vt = (vuln_type or "").strip().lower()
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if vt and (e.get("vuln_type") or "").lower() != vt:
                continue
            rows.append(e)
    except OSError:
        return []
    return rows


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def record_calibration_outcome(
        vuln_type: str,
        confidence: float,
        outcome: str,
        verdict: str = "",
        domain: str = "",
    ) -> str:
        """Feed an external ground-truth outcome into the calibration ledger.

        Use for reality the harness cannot observe itself — a triager accepting or
        rejecting a submission, a dev confirming/refuting a finding. retest and
        false-positive deletion already log automatically; this is the manual path.

        Args:
            vuln_type: Vulnerability class the confidence was for (e.g. 'sqli').
            confidence: The predicted confidence that was assigned (0.0-1.0).
            outcome: What reality showed — true_positive / false_positive
                     (aliases: accepted, rejected, duplicate, confirmed, invalid...).
            verdict: Optional original verdict string (CONFIRMED / SUSPECTED...).
            domain: Optional target the outcome came from.
        """
        y = outcome_label(outcome)
        if y is None:
            return (
                f"outcome {outcome!r} does not resolve to a positive or negative — "
                f"use true_positive/false_positive (or accepted/rejected/duplicate). "
                f"Not recorded."
            )
        ok = record_calibration(
            vuln_type, confidence, outcome,
            verdict=verdict, source="operator", domain=domain,
        )
        if not ok:
            return "Error: could not write calibration ledger."
        label = "true positive" if y == 1 else "false positive"
        return (
            f"Calibration point recorded: {vuln_type} @ {float(confidence):.2f} "
            f"→ {label}. See calibration_report()."
        )

    @mcp.tool()
    async def calibration_report(
        vuln_type: str = "",
        min_samples: int = 3,
    ) -> str:
        """Score verdict confidences against real outcomes (reliability + Brier + ECE).

        Reads the global calibration ledger of (predicted confidence → real
        outcome) pairs and reports where confidences are over/under-confident, per
        vulnerability class, with a data-driven suggested replacement for each
        hand-picked constant. Empty until retests / FP-deletions / operator outcomes
        accumulate.

        Args:
            vuln_type: Restrict to one class (empty = all classes).
            min_samples: Minimum resolved outcomes before a class is judged
                         calibrated/over/under (fewer = 'insufficient').
        """
        records = _load_ledger(vuln_type)
        if not records:
            where = f" for {vuln_type!r}" if vuln_type else ""
            return (
                f"Calibration ledger is empty{where}. It fills as findings are "
                f"re-tested (record_retest), deleted as false positives "
                f"(mark_finding_false_positive), or scored by the operator "
                f"(record_calibration_outcome)."
            )
        s = calibration_summary(records, min_samples=min_samples)
        lines = [
            f"Confidence calibration{f' — {vuln_type}' if vuln_type else ''}",
            f"  scored {s['scored']} / {s['records_total']} records "
            f"({s['unresolved']} lack ground truth)",
            f"  base rate (true-positive share): "
            f"{s['base_rate'] if s['base_rate'] is not None else 'n/a'}"
            f"   TP={s['true_positives']} FP={s['false_positives']}",
        ]
        if s["scored"] == 0:
            lines.append("  No resolved outcomes yet — nothing to score.")
            return "\n".join(lines)
        lines += [
            f"  Brier score: {s['brier_score']}  (0=perfect, lower=better)",
            f"  Expected calibration error: {s['expected_calibration_error']}  "
            f"(0=perfectly calibrated)",
            "",
            "  Reliability (predicted confidence vs observed true-positive rate):",
            f"    {'bin':<10}{'n':>4}{'pred':>8}{'actual':>8}{'gap':>8}",
        ]
        for row in s["reliability_table"]:
            lines.append(
                f"    {row['bin']:<10}{row['n']:>4}{row['mean_confidence']:>8.2f}"
                f"{row['tp_rate']:>8.2f}{row['gap']:>+8.2f}"
            )
        lines += ["", "  Per class (worst-miscalibrated first):"]
        for row in s["per_class"]:
            sug = (
                f" → suggest {row['suggested_confidence']:.2f}"
                if row["suggested_confidence"] is not None else ""
            )
            lines.append(
                f"    {row['vuln_type']:<20} n={row['n']:<3} "
                f"pred={row['mean_confidence']:.2f} actual={row['tp_rate']:.2f} "
                f"[{row['verdict']}]{sug}"
            )
        lines += [
            "",
            "  gap = predicted - actual. Positive = overconfident (verdict claims "
            "real more often than it is).",
            "  Re-tune the constants in tools/testing/_verdict.py toward each "
            "class's suggested value once n is adequate.",
        ]
        return "\n".join(lines)
