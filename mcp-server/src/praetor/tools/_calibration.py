"""Confidence calibration — measure whether verdict confidences match reality.

RLCD-inspired (TypeSafe "Jev"): a verdict's `confidence` is a *predicted
probability* that the finding is real. Praetor's constants (0.85/0.55/0.45/0.10
in `_verdict.py`) are asserted-calibrated but never validated. This module scores
them against ground truth — a finding re-confirmed on retest (true positive) or
deleted as a false positive — so the constants can be re-tuned with data instead
of eyeballed, and so `is_actionable` / Rule-33 escalation act on honest numbers.

Pure logic: no I/O, no deps. The ledger + tool live in `intel/calibration.py`.

A record is `{"vuln_type": str, "confidence": float, "outcome": str, ...}`.
Only records whose outcome resolves to a real positive/negative are scored;
`unknown` outcomes are excluded (absence of ground truth, not a data point).
"""

from __future__ import annotations

from typing import Any

# Ground-truth normalisation. A finding that was re-confirmed / regressed /
# reopened / fixed was REAL (positive). One deleted as FP, or a platform
# reject/duplicate/NA, was NOT real (negative). Anything else is unknown.
_POSITIVE = {
    "true_positive", "tp", "positive", "confirmed", "valid", "accepted",
    "real", "regressed", "reopened", "fixed", "triaged", "resolved", "paid",
}
_NEGATIVE = {
    "false_positive", "fp", "negative", "invalid", "rejected", "duplicate",
    "dupe", "na", "n/a", "not_applicable", "informative", "benign", "spam",
}


def outcome_label(outcome: str) -> int | None:
    """Map a free-text outcome to 1 (true positive), 0 (false positive), or None.

    None means "no ground truth" — the record is excluded from scoring rather
    than silently counted as a negative (Rule 13b: absence of evidence is not
    evidence of absence, applied to calibration data itself).
    """
    o = (outcome or "").strip().lower().replace("-", "_").replace(" ", "_")
    if o in _POSITIVE:
        return 1
    if o in _NEGATIVE:
        return 0
    return None


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def bin_label(conf: float, width: float = 0.1) -> str:
    """Fixed-width reliability bin label, e.g. 0.5 -> '0.5-0.6'."""
    c = _clamp(conf)
    lo = min(int(c / width) * width, 1.0 - width)
    return f"{lo:.1f}-{lo + width:.1f}"


def _scored(records: list[dict[str, Any]]) -> list[tuple[float, int, str]]:
    """Project records to (confidence, y, vuln_type), dropping unscoreable ones."""
    out: list[tuple[float, int, str]] = []
    for r in records:
        y = outcome_label(str(r.get("outcome", "")))
        if y is None:
            continue
        conf = r.get("confidence")
        if conf is None:
            continue
        try:
            c = _clamp(conf)
        except (TypeError, ValueError):
            continue
        out.append((c, y, str(r.get("vuln_type") or "").strip().lower() or "unknown"))
    return out


def brier_score(records: list[dict[str, Any]]) -> float | None:
    """Mean squared error between predicted confidence and outcome (0..1, lower
    is better). None when there is no scoreable data."""
    scored = _scored(records)
    if not scored:
        return None
    return round(sum((c - y) ** 2 for c, y, _ in scored) / len(scored), 4)


def reliability_table(records: list[dict[str, Any]], width: float = 0.1) -> list[dict[str, Any]]:
    """Per-bin reliability: predicted vs observed true-positive rate.

    Each row: {bin, n, mean_confidence, tp_rate, gap} where
    gap = mean_confidence - tp_rate (positive = overconfident in that band).
    Sorted by bin ascending. Empty bins are omitted.
    """
    scored = _scored(records)
    buckets: dict[str, list[tuple[float, int]]] = {}
    for c, y, _ in scored:
        buckets.setdefault(bin_label(c, width), []).append((c, y))
    rows: list[dict[str, Any]] = []
    for label in sorted(buckets):
        pairs = buckets[label]
        n = len(pairs)
        mean_conf = sum(c for c, _ in pairs) / n
        tp_rate = sum(y for _, y in pairs) / n
        rows.append({
            "bin": label,
            "n": n,
            "mean_confidence": round(mean_conf, 3),
            "tp_rate": round(tp_rate, 3),
            "gap": round(mean_conf - tp_rate, 3),
        })
    return rows


def expected_calibration_error(records: list[dict[str, Any]], width: float = 0.1) -> float | None:
    """ECE — sample-weighted mean |mean_confidence - tp_rate| across bins.

    0 = perfectly calibrated. None when there is no scoreable data.
    """
    scored = _scored(records)
    if not scored:
        return None
    n_total = len(scored)
    ece = 0.0
    for row in reliability_table(records, width):
        ece += (row["n"] / n_total) * abs(row["gap"])
    return round(ece, 4)


def per_class_calibration(
    records: list[dict[str, Any]],
    *,
    min_samples: int = 3,
    gap_threshold: float = 0.15,
) -> list[dict[str, Any]]:
    """Per vuln_type: mean predicted confidence vs observed true-positive rate.

    Each row: {vuln_type, n, mean_confidence, tp_rate, gap, verdict,
    suggested_confidence}. `verdict` flags miscalibration when
    |gap| > gap_threshold AND n >= min_samples:
      - 'overconfident'   mean_confidence >> tp_rate (predicts real, isn't)
      - 'underconfident'  mean_confidence << tp_rate (real more often than claimed)
      - 'calibrated'      within tolerance
      - 'insufficient'    fewer than min_samples resolved outcomes
    `suggested_confidence` = observed tp_rate (the data-driven replacement for the
    hand-picked constant), given only when n >= min_samples.

    Sorted worst-miscalibrated first so re-tuning starts where it matters.
    """
    scored = _scored(records)
    by_class: dict[str, list[tuple[float, int]]] = {}
    for c, y, vt in scored:
        by_class.setdefault(vt, []).append((c, y))
    rows: list[dict[str, Any]] = []
    for vt, pairs in by_class.items():
        n = len(pairs)
        mean_conf = sum(c for c, _ in pairs) / n
        tp_rate = sum(y for _, y in pairs) / n
        gap = mean_conf - tp_rate
        if n < min_samples:
            verdict = "insufficient"
            suggested = None
        elif gap > gap_threshold:
            verdict = "overconfident"
            suggested = round(tp_rate, 2)
        elif gap < -gap_threshold:
            verdict = "underconfident"
            suggested = round(tp_rate, 2)
        else:
            verdict = "calibrated"
            suggested = round(tp_rate, 2)
        rows.append({
            "vuln_type": vt,
            "n": n,
            "mean_confidence": round(mean_conf, 3),
            "tp_rate": round(tp_rate, 3),
            "gap": round(gap, 3),
            "verdict": verdict,
            "suggested_confidence": suggested,
        })
    # Worst |gap| among classes with enough samples first; insufficient last.
    rows.sort(key=lambda r: (r["verdict"] == "insufficient", -abs(r["gap"])))
    return rows


def calibration_summary(
    records: list[dict[str, Any]],
    *,
    min_samples: int = 3,
) -> dict[str, Any]:
    """Full calibration report over a ledger of records.

    Returns overall Brier + ECE, the reliability table, per-class breakdown, and
    counts. `scored` is the number of records with resolved ground truth;
    `unresolved` the number excluded for lacking it.
    """
    scored = _scored(records)
    n_scored = len(scored)
    n_pos = sum(y for _, y, _ in scored)
    return {
        "records_total": len(records),
        "scored": n_scored,
        "unresolved": len(records) - n_scored,
        "true_positives": n_pos,
        "false_positives": n_scored - n_pos,
        "base_rate": round(n_pos / n_scored, 3) if n_scored else None,
        "brier_score": brier_score(records),
        "expected_calibration_error": expected_calibration_error(records),
        "reliability_table": reliability_table(records),
        "per_class": per_class_calibration(records, min_samples=min_samples),
    }
