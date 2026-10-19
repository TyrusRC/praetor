"""Markdown section builders for the pentest report.

Layout follows PTES §7 (Reporting), OWASP WSTG v4.2, NIST SP 800-115:
  Classification → Context → Vulnerability → Walkthrough → Impact →
  Escalation → PoC → Reproduction → Evidence → Remediation → References
"""

from ._evidence_fmt import (
    _is_internal_evidence,
    format_poc_request, format_repro_steps,
)
from ._finding_render import build_finding_section
from ._report_sections import (
    build_executive_summary, build_methodology_section, build_coverage_section,
    build_killchain_section, build_limitations_section, build_standards_mapping,
    build_glossary, build_disclaimer,
)

__all__ = ["_is_internal_evidence", "format_poc_request", "format_repro_steps",
           "build_finding_section", "build_executive_summary",
           "build_methodology_section", "build_coverage_section",
           "build_killchain_section", "build_limitations_section",
           "build_standards_mapping", "build_glossary", "build_disclaimer"]
