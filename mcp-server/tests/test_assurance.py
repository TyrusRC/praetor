"""Assurance & reporting layer (Package 1: A+B+C).

Pure-function + JSON-load coverage only. No Burp client, no network.

- tools/assurance/_standards.py  — canonical standard checklists + class->category
  rollup, reusing framework_tags (already tested in test_w34_coverage).
- tools/assurance/coverage_map.py::build_heatmap — tested-vs-total heatmap.
- tools/assurance/dashboard.py::render_dashboard_html — self-contained offline HTML.
- tools/assurance/compliance.py::build_compliance_rollup — findings-by-control.
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestStandards(unittest.TestCase):
    def setUp(self):
        from praetor.tools.assurance import _standards
        self.s = _standards

    def test_owasp_top10_has_all_ten_categories(self):
        cats = self.s.STANDARDS["owasp_top10"]["categories"]
        self.assertEqual(len(cats), 10)
        self.assertIn("A01", cats)
        self.assertIn("A10", cats)

    def test_api_top10_has_all_ten_categories(self):
        cats = self.s.STANDARDS["api_top10"]["categories"]
        self.assertEqual(len(cats), 10)
        self.assertIn("API1", cats)

    def test_wstg_categories_present(self):
        cats = self.s.STANDARDS["wstg"]["categories"]
        self.assertIn("INPV", cats)
        self.assertIn("ATHZ", cats)

    def test_category_of_maps_sqli_to_owasp_injection(self):
        self.assertEqual(self.s.category_of("owasp_top10", "sqli"), "A03")

    def test_category_of_maps_alias_and_suffix(self):
        # framework_tags resolves aliases + suffix strip; rollup must inherit that
        self.assertEqual(self.s.category_of("owasp_top10", "sql_injection"), "A03")
        self.assertEqual(self.s.category_of("owasp_top10", "sqli_blind"), "A03")

    def test_category_of_wstg_rolls_up_to_top_category(self):
        # WSTG-INPV-05 -> INPV
        self.assertEqual(self.s.category_of("wstg", "sqli"), "INPV")

    def test_category_of_unknown_class_returns_none(self):
        self.assertIsNone(self.s.category_of("owasp_top10", "totally_made_up_xyz"))

    def test_unknown_standard_raises_keyvalue(self):
        with self.assertRaises(KeyError):
            self.s.category_of("not_a_standard", "sqli")


class TestHeatmap(unittest.TestCase):
    def setUp(self):
        from praetor.tools.assurance.coverage_map import build_heatmap
        self.build = build_heatmap

    def test_untested_category_when_no_data(self):
        hm = self.build("owasp_top10", tested_classes=set(), findings=[])
        self.assertEqual(hm["categories"]["A03"]["status"], "untested")
        self.assertEqual(hm["coverage_pct"], 0)

    def test_tested_class_marks_category_tested(self):
        hm = self.build("owasp_top10", tested_classes={"sqli"}, findings=[])
        self.assertEqual(hm["categories"]["A03"]["status"], "tested")
        self.assertGreater(hm["coverage_pct"], 0)

    def test_finding_outranks_tested(self):
        hm = self.build(
            "owasp_top10",
            tested_classes={"sqli"},
            findings=[{"vuln_type": "sqli", "status": "confirmed"}],
        )
        self.assertEqual(hm["categories"]["A03"]["status"], "findings")
        self.assertEqual(hm["categories"]["A03"]["findings"], 1)

    def test_all_categories_present_even_when_untested(self):
        hm = self.build("owasp_top10", tested_classes={"sqli"}, findings=[])
        self.assertEqual(len(hm["categories"]), 10)

    def test_coverage_pct_is_ratio_of_touched_categories(self):
        # sqli->A03, idor->A01 : 2 of 10 categories touched = 20%
        hm = self.build("owasp_top10", tested_classes={"sqli", "idor"}, findings=[])
        self.assertEqual(hm["coverage_pct"], 20)


class TestDashboard(unittest.TestCase):
    def setUp(self):
        from praetor.tools.assurance.dashboard import render_dashboard_html
        self.render = render_dashboard_html

    def test_html_is_self_contained_no_external_refs(self):
        html = self.render(
            domain="example.com",
            severity_counts={"critical": 1, "high": 2, "medium": 0, "low": 3},
            heatmap={"standard": "owasp_top10", "coverage_pct": 20, "categories": {}},
            trend=[],
            top_findings=[],
        )
        low = html.lower()
        self.assertIn("<html", low)
        self.assertNotIn("http://", low)
        self.assertNotIn("https://", low)
        self.assertNotIn("src=", low)  # no external scripts/images

    def test_html_shows_domain_and_severity(self):
        html = self.render(
            domain="acme.test",
            severity_counts={"critical": 4, "high": 0, "medium": 0, "low": 0},
            heatmap={"standard": "owasp_top10", "coverage_pct": 0, "categories": {}},
            trend=[],
            top_findings=[],
        )
        self.assertIn("acme.test", html)
        self.assertIn("4", html)


class TestCompliance(unittest.TestCase):
    def setUp(self):
        from praetor.tools.assurance.compliance import build_compliance_rollup
        self.build = build_compliance_rollup

    def test_confirmed_finding_maps_to_pci_control(self):
        roll = self.build(
            standard="pci_dss_v4",
            findings=[{"vuln_type": "sqli", "status": "confirmed", "title": "SQLi"}],
        )
        # sqli -> pci 6.2.4 per compliance_mappings.json
        self.assertIn("6.2.4", roll["controls"])
        self.assertEqual(roll["controls"]["6.2.4"]["count"], 1)

    def test_unconfirmed_findings_excluded(self):
        roll = self.build(
            standard="pci_dss_v4",
            findings=[{"vuln_type": "sqli", "status": "suspected", "title": "x"}],
        )
        self.assertEqual(roll["total_findings"], 0)

    def test_unknown_standard_raises(self):
        with self.assertRaises(KeyError):
            self.build(standard="not_a_framework", findings=[])


if __name__ == "__main__":
    unittest.main()
