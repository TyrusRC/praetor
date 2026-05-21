"""Read-only knowledge tables used by advisor.assess_finding.

Lifting these out of the inline `register()` closure cuts ~400 LOC from
advisor.py and lets the dicts stay allocated once instead of being rebuilt
on every assess_finding invocation.

Submodules:
- q5            — Q5_KEYWORDS, Q5_ALIASES, TIMING_VULN_TYPES (data tables)
- never_submit  — never_submit_types, conditional_never_submit_types,
                  never_submit_keywords, sensitive_endpoint_patterns
- gates         — AUTH_STATE_DEPENDENT, low_impact_classes
- q1_scope, q2_repro, q4_dedup, q5_evidence, q6_never_submit, q7_triager —
                  per-question `async def check(ctx) -> CheckResult` modules.
                  Each mutates ctx.issues / ctx.verdict in place AND returns
                  a CheckResult summary.

Note: q5.py remains a data-table module. The Q5 check function lives in
q5_evidence.py. The naming asymmetry is intentional — renaming q5.py's
data table would churn every import site.
"""

from typing import TypedDict


class CheckResult(TypedDict):
    """Lightweight per-question summary returned by each check(ctx).

    Each `check(ctx)` mutates ctx in place (appends to ctx.issues, may flip
    ctx.verdict / ctx.weak_evidence) AND returns a CheckResult so new-style
    tests can assert on a single question without driving the whole gate.
    """

    passed: bool
    reason: str
    evidence: dict


from .gates import AUTH_STATE_DEPENDENT, LOW_IMPACT_CLASSES  # noqa: E402,F401
from .never_submit import (  # noqa: E402,F401
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    NEVER_SUBMIT_KEYWORDS,
    NEVER_SUBMIT_TYPES,
    SENSITIVE_ENDPOINT_PATTERNS,
)
from .q5 import Q5_ALIASES, Q5_KEYWORDS, TIMING_VULN_TYPES  # noqa: E402,F401
