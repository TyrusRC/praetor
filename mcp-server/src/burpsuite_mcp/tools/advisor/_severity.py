"""Confidence + severity inference + program-policy floor.

Runs LAST. Consumes ctx.verdict, ctx.issues, ctx.weak_evidence, ctx.impact_boost
to set ctx.suggested_confidence, ctx.inferred_severity, ctx.severity_color.
"""

from ._context import AssessContext


_SEV_TO_COLOR = {
    "CRITICAL": "RED",
    "HIGH": "RED",
    "MEDIUM": "ORANGE",
    "LOW": "YELLOW",
    "INFO": "GRAY",
}


def finalize_severity(ctx: AssessContext) -> None:
    """Compute suggested_confidence, inferred_severity, severity_color.

    Also applies program-policy confidence floor (may downgrade verdict +
    append a PROGRAM POLICY ENFORCED issue).
    """
    if ctx.verdict == "DO NOT REPORT":
        ctx.suggested_confidence = 0.05
    elif ctx.verdict == "NEEDS MORE EVIDENCE":
        penalty = max(0, len(ctx.issues) - 1) * 0.05
        ctx.suggested_confidence = max(0.40, 0.65 - penalty + ctx.impact_boost)
    elif not ctx.issues:
        ctx.suggested_confidence = min(1.0, 0.92 + ctx.impact_boost)
    else:
        ctx.suggested_confidence = min(1.0, 0.80 + ctx.impact_boost)

    # Program-policy confidence floor
    if ctx.verdict == "REPORT" and ctx.program_confidence_floor > 0:
        if ctx.suggested_confidence < ctx.program_confidence_floor:
            ctx.issues.append(
                f"PROGRAM POLICY ENFORCED: program '{ctx.program.get('slug', '?')}' "
                f"sets confidence_floor={ctx.program_confidence_floor:.2f}; "
                f"current confidence is {ctx.suggested_confidence:.2f}. "
                f"This is a POLICY downgrade, not an evidence problem — "
                f"either strengthen evidence to meet the floor, OR override "
                f"with set_program_policy() if the floor itself is wrong."
            )
            ctx.verdict = "NEEDS MORE EVIDENCE"

    if ctx.verdict == "DO NOT REPORT":
        ctx.inferred_severity = "INFO"
    elif ctx.weak_evidence:
        ctx.inferred_severity = "LOW"
    else:
        ctx.inferred_severity = "MEDIUM"
    ctx.severity_color = _SEV_TO_COLOR.get(ctx.inferred_severity, "YELLOW")
