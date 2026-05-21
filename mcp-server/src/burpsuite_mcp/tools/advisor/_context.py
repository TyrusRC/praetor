"""Shared mutable state for the 7-question assess_finding pipeline.

The original `assess_finding_impl` was a single 884-line function with
interleaved Q-blocks sharing local state (`issues`, `verdict`, `weak_evidence`,
`derived_markers`, `evidence_lower`, `impact_boost`, `impact_notes`, etc.).
Splitting the questions into per-module checks would lose that shared state,
so we package it into a dataclass that the orchestrator threads through each
check function. Each check mutates ctx in place AND returns a CheckResult
summary (for telemetry / new-style tests). Behavior must match the original
function byte-for-byte.
"""

from dataclasses import dataclass, field
from functools import lru_cache
import re


@dataclass
class AssessContext:
    """Mutable state shared across the 7-question gate."""

    # ── Inputs (set once, never mutated by checks) ──
    vuln_type: str = ""
    vuln_lower: str = ""
    evidence: str = ""
    endpoint: str = ""
    parameter: str = ""
    response_diff: str = ""
    domain: str = ""
    business_context: str = ""
    environment: str = ""
    logger_index: int = -1
    human_verified: bool = False
    chain_with: list[str] = field(default_factory=list)
    reproductions: list[dict] = field(default_factory=list)
    session_name: str = ""

    # ── Override bookkeeping ──
    override_set: set[str] = field(default_factory=set)
    audit_overrides: list[str] = field(default_factory=list)

    # ── Mutable state appended/updated by checks ──
    issues: list[str] = field(default_factory=list)
    verdict: str = "REPORT"
    weak_evidence: bool = False
    derived_markers: list[str] = field(default_factory=list)
    evidence_lower: str = ""

    # ── Lookups derived once for use across multiple checks ──
    effective_domain: str = ""
    q2_class_root: str = ""
    endpoint_lower: str = ""
    endpoint_is_sensitive: bool = False
    chain_provided: bool = False

    # ── Per-program policy ──
    program: dict = field(default_factory=dict)
    never_submit_types: dict = field(default_factory=dict)
    program_confidence_floor: float = 0.0

    # ── Impact scoring (filled by _impact module) ──
    impact_boost: float = 0.0
    impact_notes: list[str] = field(default_factory=list)
    biz_data: dict = field(default_factory=dict)
    grey_box_active: bool = False

    # ── Output (filled by _severity / orchestrator) ──
    suggested_confidence: float = 0.0
    inferred_severity: str = "MEDIUM"
    severity_color: str = "YELLOW"


@lru_cache(maxsize=256)
def word_boundary_pattern(key: str) -> re.Pattern:
    """Compile + cache a `(?<![a-z])key(?![a-z])` regex.

    Several Q6/Q4 checks pattern-match dozens of NEVER-SUBMIT keys per call;
    pre-compiling at module level avoids per-call recompilation.
    """
    return re.compile(rf"(?<![a-z]){re.escape(key)}(?![a-z])")
