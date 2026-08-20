"""Q7: triager-mass-report heuristic.

Low-impact class + weak evidence + no chain → triager will mark informative.
Downgrade verdict to NEEDS MORE EVIDENCE. chain_with[] supplies the impact
context that elevates the finding above mass-report territory.
"""

from ..advisor._context import AssessContext
from . import CheckResult, LOW_IMPACT_CLASSES


async def check(ctx: AssessContext) -> CheckResult:
    if "q7_triager" in ctx.override_set:
        ctx.issues.append("Q7 OVERRIDE: triager-mass-report heuristic bypassed")
        return {"passed": True, "reason": "override", "evidence": {}}

    if ctx.chain_provided and ctx.vuln_lower in LOW_IMPACT_CLASSES:
        ctx.issues.append(
            f"Q7 SKIP: chain_with={ctx.chain_with} supplies impact context — "
            "low-impact root class is acceptable when chained"
        )
        return {"passed": True, "reason": "chained", "evidence": {}}

    if ctx.verdict == "REPORT" and ctx.weak_evidence and ctx.vuln_lower in LOW_IMPACT_CLASSES:
        ctx.issues.append(
            "Q7 TRIAGER TEST: low-impact class + weak evidence — likely marked "
            "informative. Chain with another finding first (pass chain_with=[<id>])."
        )
        ctx.verdict = "NEEDS MORE EVIDENCE"
        return {"passed": False, "reason": "triager-mass-report", "evidence": {}}

    return {"passed": True, "reason": "ok", "evidence": {}}
