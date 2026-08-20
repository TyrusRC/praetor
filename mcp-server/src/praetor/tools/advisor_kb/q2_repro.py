"""Q2: reproducibility.

- override `q2_repro` → record bypass.
- AUTH_STATE_DEPENDENT classes are EXEMPT (re-auth would destroy the state).
- Otherwise, intermittent / once / non-reproducible / could-not-reproduce in
  the evidence prose triggers Q2 FAIL (non-fatal — surfaces an issue but
  does NOT flip verdict; matches original behavior).
"""

from ..advisor._context import AssessContext
from . import CheckResult, AUTH_STATE_DEPENDENT


async def check(ctx: AssessContext) -> CheckResult:
    if "q2_repro" in ctx.override_set:
        ctx.issues.append("Q2 OVERRIDE: reproducibility check bypassed")
        return {"passed": True, "reason": "override", "evidence": {}}

    if ctx.q2_class_root in AUTH_STATE_DEPENDENT:
        ctx.issues.append(
            f"Q2 EXEMPT: '{ctx.vuln_type}' is auth-state-dependent — same-session "
            "reproduction is correct (re-auth would lose the state being tested)"
        )
        return {"passed": True, "reason": "auth-state-exempt", "evidence": {
            "class_root": ctx.q2_class_root,
        }}

    if any(w in ctx.evidence_lower for w in (
        "once", "intermittent", "one time", "non-reproducible", "could not reproduce"
    )):
        ctx.issues.append(
            "Q2 FAIL: evidence suggests non-reproducible — re-test 3+ times from clean state"
        )
        return {"passed": False, "reason": "intermittent", "evidence": {}}

    return {"passed": True, "reason": "ok", "evidence": {}}
