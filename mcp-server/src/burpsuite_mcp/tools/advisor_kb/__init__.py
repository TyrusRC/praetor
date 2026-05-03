"""Read-only knowledge tables used by advisor.assess_finding.

Lifting these out of the inline `register()` closure cuts ~400 LOC from
advisor.py and lets the dicts stay allocated once instead of being rebuilt
on every assess_finding invocation.

Submodules:
- q5            — Q5_KEYWORDS, Q5_ALIASES, TIMING_VULN_TYPES
- never_submit  — never_submit_types, conditional_never_submit_types,
                  never_submit_keywords, sensitive_endpoint_patterns
- gates         — AUTH_STATE_DEPENDENT, low_impact_classes
"""

from .gates import AUTH_STATE_DEPENDENT, LOW_IMPACT_CLASSES  # noqa: F401
from .never_submit import (  # noqa: F401
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    NEVER_SUBMIT_KEYWORDS,
    NEVER_SUBMIT_TYPES,
    SENSITIVE_ENDPOINT_PATTERNS,
)
from .q5 import Q5_ALIASES, Q5_KEYWORDS, TIMING_VULN_TYPES  # noqa: F401
