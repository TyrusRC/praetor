"""Structured verdict schema for testing/probe tools (W7).

Senior-engineer outputs: every probe returns the same shape so the orchestrator
can pipe results into `assess_finding` without re-parsing prose. The
human-readable string is surfaced at top-level `human_summary`.

Verdict semantics
-----------------
- CONFIRMED    — replay-based proof: matcher fired, replays agree, evidence
                 bound to a real Burp index.
- SUSPECTED    — strong anomaly vs baseline, but missing one of: replay-stable,
                 executable context, OOB confirmation.
- FAILED       — probe ran AND the test was VALID (the mechanism was exercised —
                 injection context entered, sink reached, payload landed — i.e. a
                 positive control passed) AND the response body showed a real
                 negative vs baseline. Only THEN is it a covered-negative. A
                 negative from an unproven/malformed test is NOT FAILED — it is
                 INCONCLUSIVE. "Absence of evidence is not evidence of absence."
- INCONCLUSIVE — probe ran but the evidence is INSUFFICIENT to call it either way:
                 test-validity unproven (payload may not have reached the sink /
                 wrong injection point / malformed), or the body signal is
                 ambiguous. NOT a finding and NOT a covered-negative — the tuple
                 stays OPEN (keep testing / fix the payload / escalate). This is the
                 third state that prevents the documented overconfidence failure of
                 declaring "benign" right after a wrong PoC.
- ERROR        — probe could not run at all (scope reject, network failure, missing
                 dependency). Caller should NOT mark as covered.

Confidence
----------
0.0 - 1.0. Calibrated so `assess_finding` Q5 floor (~0.45 default) maps to a
strong-suspected verdict. Confirmed ≥ 0.70, suspected 0.45-0.69, failed < 0.45.
"""

from __future__ import annotations

from typing import Any, Literal

Verdict = Literal["CONFIRMED", "SUSPECTED", "FAILED", "INCONCLUSIVE", "ERROR"]

_VALID = {"CONFIRMED", "SUSPECTED", "FAILED", "INCONCLUSIVE", "ERROR"}


def make_verdict(
    verdict: Verdict,
    confidence: float,
    evidence_summary: str,
    *,
    vuln_type: str | None = None,
    logger_indices: list[int] | None = None,
    proxy_indices: list[int] | None = None,
    collaborator_interactions: list[str] | None = None,
    reproductions: list[dict[str, Any]] | None = None,
    details: dict[str, Any] | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    """Build a normalised verdict dict.

    `summary` is the human-readable string, surfaced at top-level `human_summary`
    when supplied. Empty evidence lists and empty `details` are omitted from the
    returned dict (token-lean, Spec E1.2); read them via `.get(...)`.
    """
    if verdict not in _VALID:
        raise ValueError(f"invalid verdict {verdict!r}; must be one of {_VALID}")
    conf = max(0.0, min(1.0, float(confidence)))
    d = dict(details or {})
    out: dict[str, Any] = {
        "verdict": verdict,
        "confidence": round(conf, 3),
        "evidence_summary": evidence_summary,
    }
    # Token-lean (Spec E1.2): include evidence lists / details only when
    # non-empty. `to_assess_evidence` and all consumers read these via .get(),
    # so omitting an empty list is safe and saves ~4 keys on every verdict.
    if logger_indices:
        out["logger_indices"] = list(logger_indices)
    if proxy_indices:
        out["proxy_indices"] = list(proxy_indices)
    if collaborator_interactions:
        out["collaborator_interactions"] = list(collaborator_interactions)
    if reproductions:
        out["reproductions"] = list(reproductions)
    if d:
        out["details"] = d
    if vuln_type:
        out["vuln_type"] = vuln_type
    if summary is not None:
        out["human_summary"] = summary
    return out


def is_actionable(v: dict[str, Any]) -> bool:
    """True if verdict is CONFIRMED or SUSPECTED with confidence >= 0.45."""
    return v.get("verdict") == "CONFIRMED" or (
        v.get("verdict") == "SUSPECTED" and float(v.get("confidence", 0)) >= 0.45
    )


def to_assess_evidence(v: dict[str, Any]) -> dict[str, Any]:
    """Project a verdict dict into the shape `assess_finding(evidence=...)` expects.

    Picks the strongest indexable evidence first: collaborator > logger > proxy.
    """
    ev: dict[str, Any] = {"summary": v.get("evidence_summary", "")}
    if v.get("collaborator_interactions"):
        ev["collaborator_interaction_id"] = v["collaborator_interactions"][0]
    if v.get("logger_indices"):
        ev["logger_index"] = v["logger_indices"][0]
    elif v.get("proxy_indices"):
        ev["proxy_history_index"] = v["proxy_indices"][0]
    if v.get("reproductions"):
        ev["reproductions"] = v["reproductions"]
    if v.get("confidence") is not None:
        ev["confidence"] = v["confidence"]
    return ev


def error_verdict(
    message: str,
    *,
    vuln_type: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Shortcut for a tool that could not run (scope, network, missing dep).

    `reason` is a short machine-readable class for the failure — `out_of_scope`,
    `baseline_failed`, `bad_payload` — so a caller can branch on why a probe
    stopped without string-matching the message.
    """
    details: dict[str, Any] = {"error": message}
    if reason:
        details["reason"] = reason
    return make_verdict(
        "ERROR",
        0.0,
        message,
        vuln_type=vuln_type,
        details=details,
        summary=message,
    )


def inconclusive_verdict(
    message: str,
    *,
    vuln_type: str | None = None,
    reason: str | None = None,
    logger_indices: list[int] | None = None,
) -> dict[str, Any]:
    """Shortcut for a probe that RAN but produced INSUFFICIENT evidence to decide.

    Use this — not FAILED — when the test's validity is unproven (the payload may
    not have reached the sink, the injection context was never entered, the payload
    was malformed) or the body signal is ambiguous. INCONCLUSIVE is neither a finding
    nor a covered-negative: the tuple stays OPEN, so `is_actionable` is False and the
    orchestrator must keep testing (fix the payload / prove the sink / add a variant)
    or escalate — never close it as benign. This is the guard against the documented
    LLM failure of declaring "not vulnerable" right after a wrong PoC.

    `reason` is a short machine-readable class — `test_validity_unproven`,
    `ambiguous_body`, `sink_not_reached` — for callers that branch on it.
    """
    details: dict[str, Any] = {}
    if reason:
        details["reason"] = reason
    return make_verdict(
        "INCONCLUSIVE",
        0.0,
        message,
        vuln_type=vuln_type,
        logger_indices=logger_indices,
        details=details or None,
        summary=message,
    )


def verdict_from_tally(
    hits: int,
    *,
    confirmed_threshold: int = 2,
    confirmed_confidence: float = 0.85,
    suspected_confidence: float = 0.55,
    failed_confidence: float = 0.10,
) -> tuple[str, float]:
    """Common pattern: derive (verdict, confidence) from a count of positive hits.

    Used across ~20 testing tools where the canonical mapping is:
        hits >= 2 → CONFIRMED (0.85)
        hits == 1 → SUSPECTED (0.55)
        hits == 0 → FAILED    (0.10)

    Tools needing custom thresholds pass their own values; tools needing
    custom verdict logic (e.g. CONFIRMED only when a CRITICAL subset is hit)
    keep using make_verdict directly.

    Returns: (verdict_string, confidence_float).
    """
    if hits >= confirmed_threshold:
        return ("CONFIRMED", confirmed_confidence)
    if hits >= 1:
        return ("SUSPECTED", suspected_confidence)
    return ("FAILED", failed_confidence)
