"""Q1: scope verification.

Rules:
- override `q1_scope` → record the override, no scope call.
- Otherwise, in `operator` mode (default), defer scope to operator (trusted-
  authorization) and emit PASS.
- In `strict` mode with an effective_domain, call /api/scope/check; transient
  errors → SKIP, explicit out-of-scope → FAIL (verdict=DO NOT REPORT).
- No domain at all → SKIP with a hint.
"""

from burpsuite_mcp import client
from ..advisor._context import AssessContext
from . import CheckResult


async def check(ctx: AssessContext) -> CheckResult:
    if "q1_scope" in ctx.override_set:
        ctx.issues.append("Q1 OVERRIDE: scope check bypassed by operator")
        return {"passed": True, "reason": "override", "evidence": {}}

    try:
        from burpsuite_mcp.tools import _scope_mode
        mode = _scope_mode.get_mode()
    except Exception:
        mode = "operator"

    if mode == "operator":
        ctx.issues.append(
            "Q1 PASS: operator-mode (trusted-authorization) — scope check deferred"
        )
        return {"passed": True, "reason": "operator-mode", "evidence": {"mode": mode}}

    if ctx.effective_domain:
        try:
            scope_resp = await client.post(
                "/api/scope/check",
                json={
                    "url": ctx.endpoint
                    if "://" in ctx.endpoint
                    else f"https://{ctx.effective_domain}{ctx.endpoint}"
                },
            )
            if "error" in scope_resp:
                ctx.issues.append(
                    f"Q1 SKIP: scope check unavailable ({scope_resp['error'][:60]})"
                )
                return {"passed": True, "reason": "transient", "evidence": scope_resp}
            if not scope_resp.get("in_scope", False):
                ctx.issues.append(
                    f"Q1 FAIL: endpoint {ctx.endpoint} is OUT OF SCOPE — do not report"
                )
                ctx.verdict = "DO NOT REPORT"
                return {"passed": False, "reason": "out-of-scope", "evidence": scope_resp}
            return {"passed": True, "reason": "in-scope", "evidence": scope_resp}
        except Exception as e:
            ctx.issues.append(f"Q1 SKIP: scope check raised ({type(e).__name__})")
            return {"passed": True, "reason": "exception", "evidence": {"exc": type(e).__name__}}

    ctx.issues.append(
        "Q1 SKIP: pass `domain=...` (or full URL endpoint) to enable scope verification"
    )
    return {"passed": True, "reason": "no-domain", "evidence": {}}
