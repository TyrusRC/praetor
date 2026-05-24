"""assess_finding: 7-Question Validation Gate orchestrator.

Thin orchestrator that builds an AssessContext, runs auto-evidence augmentation,
loops through per-question modules (q1..q7), then applies impact scoring and
severity finalization. Behavior must match the pre-refactor monolith
byte-for-byte; the tests/_baseline_capture.py harness verifies this.

Q3 has no discrete check — impact is folded into severity scoring. The
orchestrator loop intentionally skips q3 to preserve exact byte ordering of
the issues list. See advisor_kb/q3_impact.py for the symmetry placeholder.
"""

from urllib.parse import urlparse

# Re-exported for tests that patch `burpsuite_mcp.tools.advisor.assess.client.*`.
# The actual HTTP calls happen inside _evidence_augment + advisor_kb.q1_scope,
# but both reference the same `burpsuite_mcp.client` module object, so patching
# attributes on this reference propagates everywhere.
from burpsuite_mcp import client  # noqa: F401

from ..advisor_kb import (
    NEVER_SUBMIT_TYPES,
    SENSITIVE_ENDPOINT_PATTERNS,
    q1_scope,
    q2_repro,
    q4_dedup,
    q5_evidence,
    q6_never_submit,
    q7_triager,
)
from ._context import AssessContext
from ._evidence_augment import augment_evidence
from ._impact import apply_impact_scoring
from ._severity import finalize_severity


# Ordered per-question chain. Q6 runs BEFORE Q5 (preserves original issue
# ordering — Q6 NEVER SUBMIT messages come before Q5 evidence flags in the
# baseline). Q4 runs AFTER Q5 (only fires when verdict is still REPORT).
# Q7 last. Q3 intentionally absent — no source gate.
QUESTION_CHAIN = (
    ("q1_scope", q1_scope),
    ("q2_repro", q2_repro),
    ("q6_never_submit", q6_never_submit),
    ("q5_evidence", q5_evidence),
    ("q4_dedup", q4_dedup),
    ("q7_triager", q7_triager),
)


def _build_context(
    vuln_type: str,
    evidence: str,
    endpoint: str,
    parameter: str,
    response_diff: str,
    domain: str,
    business_context: str,
    environment: str,
    logger_index: int,
    human_verified: bool,
    overrides: list[str] | None,
    chain_with: list[str] | None,
    reproductions: list[dict] | None,
    session_name: str,
    intensity: str = "normal",
) -> AssessContext:
    """Allocate + populate the per-call AssessContext."""
    norm_intensity = (intensity or "normal").strip().lower()
    if norm_intensity not in {"safe", "normal", "aggressive"}:
        norm_intensity = "normal"
    ctx = AssessContext(
        vuln_type=vuln_type,
        vuln_lower=vuln_type.lower(),
        evidence=evidence,
        endpoint=endpoint,
        parameter=parameter,
        response_diff=response_diff,
        domain=domain,
        business_context=business_context,
        environment=environment,
        logger_index=logger_index,
        human_verified=human_verified,
        chain_with=chain_with or [],
        reproductions=reproductions or [],
        session_name=session_name,
        intensity=norm_intensity,
        evidence_lower=evidence.lower(),
        never_submit_types=dict(NEVER_SUBMIT_TYPES),
    )

    # Override bookkeeping
    for ov in (overrides or []):
        gate = (ov.split(":", 1)[0] if ":" in ov else ov).strip().lower()
        if gate:
            ctx.override_set.add(gate)
            ctx.audit_overrides.append(ov)

    # Effective domain (used by Q1 scope check)
    ctx.effective_domain = domain
    if not ctx.effective_domain and "://" in endpoint:
        try:
            ctx.effective_domain = urlparse(endpoint).hostname or ""
        except Exception:
            ctx.effective_domain = ""

    # Q2 class-root strip
    root = ctx.vuln_lower
    for sep in ("_blind", "_time", "_stored", "_reflected"):
        if root.endswith(sep):
            root = root[: -len(sep)]
            break
    ctx.q2_class_root = root

    # Endpoint sensitivity (used by Q6 conditional)
    ctx.endpoint_lower = (endpoint or "").lower()
    ctx.endpoint_is_sensitive = any(
        p in ctx.endpoint_lower for p in SENSITIVE_ENDPOINT_PATTERNS
    )
    ctx.chain_provided = bool(chain_with)
    return ctx


def _apply_program_policy(ctx: AssessContext) -> None:
    """Merge persisted per-program policy onto NEVER_SUBMIT defaults."""
    try:
        from burpsuite_mcp.tools.intel import load_active_program_policy
        program = load_active_program_policy()
    except Exception:
        program = {}
    ctx.program = program
    for k in program.get("never_submit_remove", []) or []:
        ctx.never_submit_types.pop(k, None)
    for k in program.get("never_submit_add", []) or []:
        ctx.never_submit_types.setdefault(
            k, f"Program-specific NEVER SUBMIT override ({k})"
        )
    ctx.program_confidence_floor = float(program.get("confidence_floor", 0.0) or 0.0)


def _render(ctx: AssessContext) -> str:
    """Render the final string output. Matches pre-refactor formatting."""
    program_banner = (
        f"PROGRAM: {ctx.program.get('slug')}"
        if ctx.program.get("slug")
        else "PROGRAM: DEFAULT (no policy set; consider set_program_policy)"
    )

    if not ctx.issues:
        compact = (
            f"VERDICT: {ctx.verdict} | {ctx.inferred_severity} [{ctx.severity_color}] | "
            f"conf={ctx.suggested_confidence:.2f} | All 7 PASS\n"
            f"  Next: save_finding(vuln_type='{ctx.vuln_type}', endpoint='{ctx.endpoint}', "
            f"confidence={ctx.suggested_confidence:.2f}, severity='{ctx.inferred_severity}')"
        )
        if program_banner.strip():
            compact = f"{program_banner}\n{compact}"
        extras = []
        if ctx.derived_markers:
            extras.append(f"  Auto-derived: {', '.join(ctx.derived_markers[:4])}")
        if ctx.audit_overrides:
            extras.append(f"  Overrides: {'; '.join(ctx.audit_overrides)}")
        if ctx.impact_notes:
            extras.append("  Impact: " + " | ".join(ctx.impact_notes[:3]))
        if extras:
            compact += "\n" + "\n".join(extras)
        return compact

    lines = [f"VERDICT: {ctx.verdict}"]
    lines.append(f"  {program_banner}")
    lines.append(f"  Type: {ctx.vuln_type}")
    lines.append(f"  Endpoint: {ctx.endpoint}")
    if ctx.parameter:
        lines.append(f"  Parameter: {ctx.parameter}")
    lines.append(f"  Severity (inferred): {ctx.inferred_severity} [color={ctx.severity_color}]")
    lines.append(f"  Confidence (separate from color): {ctx.suggested_confidence:.2f}")
    if ctx.intensity and ctx.intensity != "normal":
        if ctx.intensity == "safe":
            lines.append(
                "  Intensity: SAFE — suppress state-mutating probe variants "
                "(POST/PUT/DELETE/PATCH unless idempotent); OOB requires Collaborator."
            )
        elif ctx.intensity == "aggressive":
            lines.append(
                "  Intensity: AGGRESSIVE — Q7 mass-report downgrade relaxed; "
                "staging / pre-engagement context assumed."
            )
    if ctx.derived_markers:
        lines.append(f"  Auto-derived markers: {', '.join(ctx.derived_markers[:8])}")
    if ctx.audit_overrides:
        lines.append(f"  Operator overrides: {'; '.join(ctx.audit_overrides)}")
    if ctx.impact_notes:
        lines.append("\n  Impact context:")
        for n in ctx.impact_notes:
            lines.append(f"    + {n}")
    lines.append(f"\n  Gate issues ({len(ctx.issues)}):")
    for issue in ctx.issues:
        lines.append(f"    - {issue}")

    if ctx.verdict == "DO NOT REPORT":
        lines.append("\n  Action: Do not report. Move to next target/parameter.")
    elif ctx.verdict == "NEEDS MORE EVIDENCE":
        lines.append(
            "\n  Action: Strengthen the flagged evidence items, then re-assess before save_finding."
            "\n  Fast path: pass logger_index=<N> to auto-derive evidence, "
            "or human_verified=True if confirmed in Burp UI."
        )
    else:
        lines.append(
            f"\n  Action: Address the issues above, then save_finding(confidence={ctx.suggested_confidence:.2f})."
        )

    return "\n".join(lines)


async def assess_finding_impl(
    vuln_type: str,
    evidence: str,
    endpoint: str,
    parameter: str = "",
    response_diff: str = "",
    domain: str = "",
    business_context: str = "",
    environment: str = "",
    logger_index: int = -1,
    human_verified: bool = False,
    overrides: list[str] | None = None,
    chain_with: list[str] | None = None,
    reproductions: list[dict] | None = None,
    session_name: str = "",
    intensity: str = "normal",
) -> str:
    """Run the 7-question validation gate and return a formatted verdict string.

    Orchestrator only — per-question logic lives in advisor_kb/q{1,2,4,5,6,7}_*.py.
    Impact scoring lives in _impact.py. Severity inference in _severity.py.
    """
    ctx = _build_context(
        vuln_type, evidence, endpoint, parameter, response_diff,
        domain, business_context, environment, logger_index,
        human_verified, overrides, chain_with, reproductions, session_name,
        intensity,
    )

    # R1: auto-derive markers from logger_index (mutates ctx.derived_markers
    # and ctx.evidence_lower). Runs BEFORE the question loop so Q5/Q6
    # see the augmented evidence.
    await augment_evidence(ctx)

    # Merge per-program policy onto NEVER_SUBMIT defaults.
    _apply_program_policy(ctx)

    # Run the per-question chain in the documented order.
    for _name, module in QUESTION_CHAIN:
        await module.check(ctx)

    # "Any weak-evidence alone downgrades from REPORT to NEEDS MORE EVIDENCE"
    # — preserves the post-question fall-through in the original monolith.
    if ctx.verdict == "REPORT" and ctx.weak_evidence:
        ctx.verdict = "NEEDS MORE EVIDENCE"

    # Impact scoring runs AFTER questions, BEFORE severity finalization.
    await apply_impact_scoring(ctx)

    # Final confidence + severity + program-policy floor.
    finalize_severity(ctx)

    return _render(ctx)
