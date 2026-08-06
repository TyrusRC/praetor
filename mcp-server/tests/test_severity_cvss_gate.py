"""Severity <-> CVSS 4.0 coupling, risk ordering, and the report fields the
writeup projects.

Regression cover for the operator report: "findings must carry a CVSS that
matches their severity, higher-severity findings must float to the top, and
nothing may be stated that was not actually captured."
"""

import unittest

from burpsuite_mcp.tools.notes._projection import render_finding_md
from burpsuite_mcp.tools.report.platforms import format_platform_finding
from burpsuite_mcp.tools.report.severity import (
    cvss4_for_finding,
    severity_cap_for,
    severity_cvss_conflict,
    sort_findings_by_risk,
)


class TestCvssDerivation(unittest.TestCase):
    def test_vector_comes_from_class_not_from_severity_label(self):
        """Same claimed severity, different classes -> different vectors."""
        sqli, _ = cvss4_for_finding("sqli")
        info, _ = cvss4_for_finding("info_disclosure")
        self.assertNotEqual(sqli, info)
        self.assertTrue(sqli.startswith("CVSS:4.0/"))

    def test_rce_scores_higher_band_than_info_disclosure(self):
        _, rce_band = cvss4_for_finding("rce")
        _, info_band = cvss4_for_finding("info_disclosure")
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.assertGreater(order.index(rce_band), order.index(info_band))

    def test_explicit_vector_wins_when_valid(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        got, _ = cvss4_for_finding("info_disclosure", explicit_vector=v)
        self.assertEqual(got, v)

    def test_malformed_explicit_vector_falls_back_to_derived(self):
        got, band = cvss4_for_finding("sqli", explicit_vector="not-a-vector")
        self.assertTrue(got.startswith("CVSS:4.0/"))
        self.assertTrue(band)

    def test_evidence_shape_flags_move_the_vector(self):
        plain, _ = cvss4_for_finding("idor", evidence={})
        admin, _ = cvss4_for_finding("idor", evidence={"requires_admin": True})
        self.assertIn("PR:H", admin)
        self.assertNotEqual(plain, admin)


class TestSeverityConflict(unittest.TestCase):
    def test_agreement_is_silent(self):
        self.assertEqual(severity_cvss_conflict("HIGH", "HIGH"), "")

    def test_one_band_gap_is_within_scorer_tolerance(self):
        """The band function is approximate; +/-1 must not block a save."""
        self.assertEqual(severity_cvss_conflict("HIGH", "MEDIUM"), "")
        self.assertEqual(severity_cvss_conflict("MEDIUM", "HIGH"), "")

    def test_inflation_is_reported(self):
        msg = severity_cvss_conflict("CRITICAL", "LOW")
        self.assertIn("above", msg)
        self.assertIn("LOW", msg)

    def test_understatement_is_reported(self):
        msg = severity_cvss_conflict("LOW", "CRITICAL")
        self.assertIn("below", msg)

    def test_capped_class_may_sit_below_its_own_vector(self):
        """info_disclosure caps at LOW but its vector scores Medium by design."""
        self.assertEqual(severity_cvss_conflict("INFO", "MEDIUM", cap="LOW"), "")

    def test_capped_class_still_conflicts_when_claimed_above_the_cap(self):
        self.assertIn("above", severity_cvss_conflict("CRITICAL", "MEDIUM", cap="LOW"))

    def test_unknown_band_is_not_a_conflict(self):
        self.assertEqual(severity_cvss_conflict("HIGH", ""), "")


class TestSeverityCap(unittest.TestCase):
    def test_capped_class_is_reported(self):
        self.assertEqual(severity_cap_for("info_disclosure"), "LOW")

    def test_uncapped_class_returns_empty(self):
        self.assertEqual(severity_cap_for("sqli"), "")

    def test_title_fallback_only_applies_without_a_matching_vuln_type(self):
        self.assertEqual(severity_cap_for("", "Self-XSS in profile"), "INFO")


class TestRiskOrdering(unittest.TestCase):
    def test_higher_severity_floats_to_top(self):
        findings = [
            {"id": "f001", "severity": "LOW"},
            {"id": "f002", "severity": "CRITICAL"},
            {"id": "f003", "severity": "MEDIUM"},
        ]
        got = [f["id"] for f in sort_findings_by_risk(findings)]
        self.assertEqual(got, ["f002", "f003", "f001"])

    def test_reseverity_moves_an_old_finding_up(self):
        findings = [
            {"id": "f001", "severity": "INFO"},
            {"id": "f002", "severity": "LOW"},
        ]
        findings[0]["severity"] = "HIGH"  # operator re-rates f001
        self.assertEqual(sort_findings_by_risk(findings)[0]["id"], "f001")

    def test_cvss_band_breaks_severity_ties(self):
        findings = [
            {"id": "f001", "severity": "HIGH", "cvss4_severity": "HIGH"},
            {"id": "f002", "severity": "HIGH", "cvss4_severity": "CRITICAL"},
        ]
        self.assertEqual(sort_findings_by_risk(findings)[0]["id"], "f002")

    def test_ordering_is_stable_for_identical_risk(self):
        findings = [
            {"id": "f002", "severity": "HIGH", "confidence": 0.9},
            {"id": "f001", "severity": "HIGH", "confidence": 0.9},
        ]
        self.assertEqual([f["id"] for f in sort_findings_by_risk(findings)], ["f001", "f002"])


class TestNoFabricatedReportContent(unittest.TestCase):
    """A section with no stored source must read as missing, not as a claim."""

    BARE = {
        "id": "f001", "title": "Reflected value", "vuln_type": "info_disclosure",
        "severity": "LOW", "endpoint": "/api/x", "evidence": {"logger_index": 5},
    }

    def test_platform_output_does_not_invent_impact(self):
        out = format_platform_finding(dict(self.BARE), "hackerone", "example.com")
        self.assertNotIn("access unauthorized resources", out)
        self.assertIn("NOT SUPPLIED", out)

    def test_platform_output_does_not_invent_reproduction_steps(self):
        out = format_platform_finding(dict(self.BARE), "hackerone", "example.com")
        self.assertNotIn("Authenticate (or skip if unauth)", out)

    def test_platform_cvss_is_not_derived_from_severity(self):
        low = format_platform_finding(
            {**self.BARE, "vuln_type": "rce", "severity": "LOW"}, "hackerone", "example.com"
        )
        # The vector reflects RCE, so it disagrees with the LOW label and says so.
        self.assertIn("reconcile before submitting", low)

    def test_platform_strips_burp_indices(self):
        out = format_platform_finding(dict(self.BARE), "hackerone", "example.com")
        self.assertNotIn("logger_index", out)

    def test_projection_omits_sections_with_no_stored_source(self):
        md = render_finding_md(dict(self.BARE))
        self.assertNotIn("## Impact", md)
        self.assertNotIn("## Remediation", md)
        self.assertNotIn("## PoC", md)

    def test_projection_renders_stored_sections(self):
        md = render_finding_md({
            **self.BARE,
            "impact": "Reads another tenant's invoice PDF.",
            "remediation": "Scope the lookup to the caller's tenant.",
            "poc_request": "GET /api/x?id=2 HTTP/1.1",
            "reproduction_steps": ["Log in as tenant A", "Request id=2"],
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "cvss4_severity": "HIGH",
            "cwe": "CWE-639",
        })
        self.assertIn("Reads another tenant's invoice PDF.", md)
        self.assertIn("## Remediation", md)
        self.assertIn("## PoC Request", md)
        self.assertIn("1. Log in as tenant A", md)
        self.assertIn("CWE-639", md)
        self.assertIn("scores HIGH", md)


if __name__ == "__main__":
    unittest.main()


class TestReportCountHygiene(unittest.TestCase):
    """Rule 16a: activity tallies measure effort, not risk. Client output omits them."""

    COVERAGE = {
        "knowledge_version": "42",
        "entries": [
            {"categories_tested": ["sqli", "xss"]},
            {"categories_tested": ["sqli"]},
        ],
    }

    def test_client_coverage_names_classes_without_counts(self):
        from burpsuite_mcp.tools.report.builders import build_coverage_section
        out = build_coverage_section(self.COVERAGE, internal=False)
        self.assertIn("sqli", out)
        self.assertNotIn("Total parameters tested", out)
        self.assertNotIn("Parameters Tested", out)
        self.assertNotIn("Knowledge base version", out)

    def test_internal_coverage_keeps_the_tallies(self):
        from burpsuite_mcp.tools.report.builders import build_coverage_section
        out = build_coverage_section(self.COVERAGE, internal=True)
        self.assertIn("Total parameters tested: 2", out.replace("**", ""))
        self.assertIn("Knowledge base version", out)

    def test_empty_coverage_renders_nothing(self):
        from burpsuite_mcp.tools.report.builders import build_coverage_section
        self.assertEqual(build_coverage_section({}, internal=True), "")

    def test_methodology_carries_no_capability_tallies(self):
        from burpsuite_mcp.tools.report.builders import build_methodology_section
        out = build_methodology_section()
        self.assertNotIn("25+", out)
        self.assertNotIn("Claude", out)


class TestFieldTestRegressions(unittest.TestCase):
    """Both found on a live engagement against a real target."""

    def test_custom_index_keys_are_stripped_from_client_reports(self):
        """An operator's own *_index labels are still Burp bookkeeping."""
        from burpsuite_mcp.tools.report.builders import build_finding_section
        out = build_finding_section({
            "title": "SQLi", "severity": "CRITICAL", "vuln_type": "sqli",
            "endpoint": "/x", "impact": "dumps users",
            "evidence": {"true_branch_index": 118, "false_branch_index": 119,
                         "quote_break_index": 117, "logger_index": 119},
        }, 1, internal=False)
        for k in ("true_branch_index", "false_branch_index", "quote_break_index", "logger_index"):
            self.assertNotIn(k, out)

    def test_internal_report_keeps_them(self):
        from burpsuite_mcp.tools.report.builders import build_finding_section
        out = build_finding_section({
            "title": "SQLi", "severity": "CRITICAL", "vuln_type": "sqli",
            "endpoint": "/x", "evidence": {"true_branch_index": 118},
        }, 1, internal=True)
        self.assertIn("true_branch_index", out)

    def test_path_traversal_does_not_score_as_info_disclosure(self):
        """A HIGH arbitrary-file-read scored VC:L because the class was unmapped."""
        traversal, _ = cvss4_for_finding("path_traversal")
        info, _ = cvss4_for_finding("info_disclosure")
        self.assertNotEqual(traversal, info)
        self.assertIn("VC:H", traversal)

    def test_class_spelling_variants_share_a_vector(self):
        for alias, canonical in (("xss_reflected", "xss"), ("bola", "idor"),
                                 ("account_takeover", "ato"), ("sqli_union", "sqli")):
            self.assertEqual(cvss4_for_finding(alias)[0], cvss4_for_finding(canonical)[0],
                             f"{alias} should score as {canonical}")
