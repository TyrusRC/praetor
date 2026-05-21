"""Q5: evidence quality + timing-replay rule.

- human_verified=True → SKIP (audit-logged).
- override `q5_evidence` → SKIP.
- vuln_type maps via Q5_ALIASES to a Q5_KEYWORDS class; if no keyword
  matches the evidence prose, mark WEAK.
- Unknown vuln_type → WEAK (preserves R2 safe-default).
- TIMING_VULN_TYPES require >=3 reproductions[] entries OR a prose marker
  (3x / 3/3 / confirmed 3 / repeated 3 / consistent across).

Q5 may mutate ctx.weak_evidence (read later by Q7 and severity scoring).
"""

from ..advisor._context import AssessContext
from . import CheckResult, Q5_ALIASES, Q5_KEYWORDS, TIMING_VULN_TYPES


async def check(ctx: AssessContext) -> CheckResult:
    if ctx.human_verified:
        ctx.issues.append(
            "Q5 SKIP: human_verified=True (operator confirmed in Burp UI/browser)"
        )
        ctx.audit_overrides.append("q5_evidence:human_verified")
        _timing_check(ctx)
        return {"passed": True, "reason": "human_verified", "evidence": {}}

    if "q5_evidence" in ctx.override_set:
        ctx.issues.append("Q5 OVERRIDE: evidence gate bypassed by operator")
        _timing_check(ctx)
        return {"passed": True, "reason": "override", "evidence": {}}

    q5_class = Q5_ALIASES.get(ctx.vuln_lower, ctx.vuln_lower)

    if q5_class in Q5_KEYWORDS:
        keywords = Q5_KEYWORDS[q5_class]
        strong = any(k in ctx.evidence_lower for k in keywords)
        if strong and ctx.derived_markers:
            ctx.issues.append(
                f"Q5 SATISFIED: auto-derived markers from logger_index={ctx.logger_index} "
                f"({', '.join(ctx.derived_markers[:4])}"
                f"{', ...' if len(ctx.derived_markers) > 4 else ''})"
            )
        if not strong:
            ctx.issues.append(
                f"Q5 WEAK EVIDENCE: {q5_class} needs at least one of: "
                f"{', '.join(keywords[:6])}, ... ({len(keywords)} accepted markers). "
                f"Pass logger_index=<N> to auto-derive, or human_verified=True if confirmed in UI."
            )
            ctx.weak_evidence = True
    else:
        ctx.issues.append(
            f"Q5 UNKNOWN VULN TYPE: '{ctx.vuln_type}' has no class-specific keyword set. "
            f"Available classes: {', '.join(sorted(Q5_KEYWORDS.keys()))}. "
            f"Either retag, pass human_verified=True, or overrides=['q5_evidence:<reason>']."
        )
        ctx.weak_evidence = True

    _timing_check(ctx)

    return {
        "passed": not ctx.weak_evidence,
        "reason": "ok" if not ctx.weak_evidence else "weak",
        "evidence": {"class": q5_class, "weak": ctx.weak_evidence},
    }


def _timing_check(ctx: AssessContext) -> None:
    """Append Q5 TIMING markers when applicable. Preserves ordering: runs
    AFTER the keyword check, regardless of skip path."""
    if ctx.vuln_lower not in TIMING_VULN_TYPES:
        return
    if "q5_evidence" in ctx.override_set or ctx.human_verified:
        return
    replay_count = len(ctx.reproductions or [])
    has_replays = (
        replay_count >= 3
        or any(
            w in ctx.evidence_lower
            for w in ("3x", "three iterations", "3/3", "3 consistent",
                      "consistent across", "confirmed 3", "3 repeats", "repeated 3")
        )
    )
    if has_replays and replay_count >= 3:
        n_with_logger = sum(
            1 for r in ctx.reproductions
            if isinstance(r, dict) and "logger_index" in r
        )
        ctx.issues.append(
            f"Q5 TIMING SATISFIED: reproductions[] has {replay_count} entries "
            f"({n_with_logger} with logger_index)"
        )
    if not has_replays:
        ctx.issues.append(
            "Q5 TIMING RULE: timing/blind vuln types require 3+ consistent "
            "iterations — pass reproductions=[{logger_index, elapsed_ms, status_code}, ...] "
            "with len>=3, OR include '3/3' / 'confirmed 3' in evidence text"
        )
        ctx.weak_evidence = True
