"""Q6: NEVER SUBMIT classification (type-match + keyword-match).

Two stages — type-match (against vuln_lower) and keyword-match (against
evidence_lower). Conditional classes pass through when chain_with is
provided or when the endpoint matches a sensitive pattern. The keyword
stage honors a 24-char negation window so prose like "not a stack trace"
doesn't self-flag.
"""

from ..advisor._context import AssessContext, word_boundary_pattern
from . import (
    CheckResult,
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    NEVER_SUBMIT_KEYWORDS,
)


# Conditional classes that flip from NEVER SUBMIT to reportable when the
# endpoint matches a sensitive pattern (auth, reset, OTP, payment, etc.).
# cors_no_creds / version_disclosure are NOT here — they require an explicit
# chain to flip.
ENDPOINT_GATED_KEYS = (
    "rate_limit", "clickjacking", "csrf_logout",
    "host_header_no_cache", "options_method",
)


async def check(ctx: AssessContext) -> CheckResult:
    if "q6_never_submit" in ctx.override_set:
        ctx.issues.append(
            "Q6 OVERRIDE: NEVER SUBMIT bypass — must include chain_with[] in save_finding"
        )
        return {"passed": True, "reason": "override", "evidence": {}}

    matched_key = None

    # ── Stage 1: hard NEVER SUBMIT type match ──
    for ns_key, ns_reason in ctx.never_submit_types.items():
        if word_boundary_pattern(ns_key).search(ctx.vuln_lower):
            if ctx.chain_provided:
                ctx.issues.append(
                    f"Q6 NEVER SUBMIT (chained): {ns_reason}. chain_with={ctx.chain_with} — "
                    f"will pass save_finding if anchors are confirmed and not stale."
                )
            else:
                ctx.issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                ctx.verdict = "DO NOT REPORT"
            matched_key = ns_key
            break

    # ── Stage 2: conditional NEVER SUBMIT ──
    # Only run when verdict still REPORT (matches original short-circuit).
    if ctx.verdict == "REPORT" and matched_key is None:
        for ns_key, ns_reason in CONDITIONAL_NEVER_SUBMIT_TYPES.items():
            if not word_boundary_pattern(ns_key).search(ctx.vuln_lower):
                continue
            if ctx.chain_provided:
                ctx.issues.append(
                    f"Q6 CONDITIONAL (chained): {ns_reason}. chain_with={ctx.chain_with}."
                )
                matched_key = ns_key
                break
            if any(ns_key.startswith(prefix) for prefix in ENDPOINT_GATED_KEYS) \
                    and ctx.endpoint_is_sensitive:
                ctx.issues.append(
                    f"Q6 CONDITIONAL PASS: '{ns_key}' on sensitive endpoint ({ctx.endpoint}) "
                    "— reportable; sensitive-flow impact applies."
                )
                matched_key = ns_key
                break
            ctx.issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
            ctx.verdict = "DO NOT REPORT"
            matched_key = ns_key
            break

    # ── Stage 3: keyword-match in evidence (with negation guard) ──
    if ctx.verdict == "REPORT":
        negation_window = 24
        negators = (
            " not ", " no ", "isn't ", "is not", "without ", "instead of",
            "ruled out", "not a ", "not just",
        )
        for ns_key, ns_reason in NEVER_SUBMIT_KEYWORDS.items():
            m = word_boundary_pattern(ns_key).search(ctx.evidence_lower)
            if not m:
                continue
            lookback = ctx.evidence_lower[max(0, m.start() - negation_window):m.start()]
            if any(neg in lookback for neg in negators):
                continue
            if ctx.chain_provided:
                ctx.issues.append(
                    f"Q6 NEVER SUBMIT (chained): {ns_reason}. chain_with={ctx.chain_with}."
                )
            else:
                ctx.issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                ctx.verdict = "DO NOT REPORT"
            matched_key = ns_key
            break

    passed = ctx.verdict != "DO NOT REPORT"
    return {
        "passed": passed,
        "reason": "match" if matched_key else "no-match",
        "evidence": {"matched_key": matched_key},
    }
