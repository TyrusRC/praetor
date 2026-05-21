"""Q3: impact placeholder.

The 7-Question Validation Gate documents Q3 as "Real impact? What can an
attacker actually DO?" — but the original assess_finding_impl has no
discrete Q3 gate. Impact is folded into severity scoring (advisor._impact)
and Q7 (LOW_IMPACT_CLASSES + triager-mass-report heuristic).

This module exists for symmetry with the documented 7-question structure
and to give new-style tests a stable per-question import point. It is a
no-op pass that delegates real impact assessment to _impact.apply_impact_scoring
which runs AFTER all checks. Do NOT call from the orchestrator; the
orchestrator skips q3 to preserve exact byte-for-byte behavior.
"""

from ..advisor._context import AssessContext
from . import CheckResult


async def check(ctx: AssessContext) -> CheckResult:
    """No-op. Impact scoring runs as a post-question step in _impact.py."""
    return {
        "passed": True,
        "reason": "delegated-to-impact-scoring",
        "evidence": {
            "note": "Q3 has no discrete gate; see advisor._impact.apply_impact_scoring",
            "impact_boost": ctx.impact_boost,
        },
    }
