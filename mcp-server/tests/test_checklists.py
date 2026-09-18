"""Detailed per-test-case checklists (OWASP AI Testing Guide seeded)."""

import unittest

from praetor.tools.assurance._checklists import (
    checklist_for,
    next_open_items,
    render_checklist,
    CHECKLISTS,
)
from praetor.tools.assurance._standards import STANDARDS


class ChecklistCatalogTest(unittest.TestCase):
    def test_ai_catalog_is_complete_32(self):
        cases = checklist_for("ai_testing")
        self.assertEqual(len(cases), 32)  # 14 + 7 + 6 + 5

    def test_every_ai_case_category_is_a_real_standard_category(self):
        valid = set(STANDARDS["ai_testing"]["categories"])
        for c in checklist_for("ai_testing"):
            self.assertIn(c["category"], valid, f"{c['id']} bad category")
            self.assertTrue(c["id"] and c["name"] and c["tool"])

    def test_domain_counts_per_category(self):
        by = {}
        for c in checklist_for("ai_testing"):
            by[c["category"]] = by.get(c["category"], 0) + 1
        self.assertEqual(by, {"APP": 14, "MODEL": 7, "INFRA": 6, "DATA": 5})

    def test_unknown_standard_empty(self):
        self.assertEqual(checklist_for("nope"), [])

    def test_wstg_catalog_complete_and_categories_valid(self):
        w = checklist_for("wstg")
        self.assertGreaterEqual(len(w), 110)  # WSTG v4.2 full list
        valid = set(STANDARDS["wstg"]["categories"])
        for c in w:
            self.assertIn(c["category"], valid, f"{c['id']} bad category")
            self.assertTrue(c["name"] and c["tool"])
        # INJT test ids roll up to the INPV standard category
        sqli = [c for c in w if c["id"] == "WSTG-INJT-05"][0]
        self.assertEqual(sqli["category"], "INPV")


class RenderChecklistTest(unittest.TestCase):
    def test_renders_items_and_open_count(self):
        cases = checklist_for("ai_testing")
        out = render_checklist("ai_testing", "OWASP AI Testing Guide", cases, set())
        self.assertIn("AITG-APP-01", out)
        self.assertIn("32 OPEN of 32", out)  # nothing touched/confirmed
        self.assertIn("-> ", out)  # tool mapping shown

    def test_touched_category_marks_items(self):
        cases = checklist_for("ai_testing")
        out = render_checklist("ai_testing", "OWASP AI Testing Guide", cases, {"APP"})
        # 14 APP items become category-touched -> 32-14 = 18 OPEN
        self.assertIn("18 OPEN of 32", out)

    def test_explicit_item_status_overrides_category(self):
        cases = checklist_for("ai_testing")
        status = {"ai_testing:AITG-APP-01": {"status": "confirmed", "note": "garak clean"},
                  "ai_testing:AITG-MOD-01": {"status": "not_applicable", "note": "no model access"}}
        out = render_checklist("ai_testing", "OWASP AI Testing Guide", cases, set(), status)
        self.assertIn("[x] AITG-APP-01", out)
        self.assertIn("[-] AITG-MOD-01", out)
        self.assertIn("(garak clean)", out)
        self.assertIn("2 confirmed/NA", out)


class AutoTestDriverTest(unittest.TestCase):
    def test_full_coverage_returns_all_open_in_catalog_order(self):
        cases = checklist_for("wstg")
        plan = next_open_items("wstg", cases, {}, set(), "full_coverage")
        self.assertEqual(len(plan), len(cases))
        self.assertEqual(plan[0]["id"], cases[0]["id"])

    def test_confirmed_items_drop_out(self):
        cases = checklist_for("wstg")
        st = {"wstg:WSTG-INJT-05": {"status": "confirmed"}}
        ids = {c["id"] for c in next_open_items("wstg", cases, st, set(), "full_coverage")}
        self.assertNotIn("WSTG-INJT-05", ids)

    def test_high_impact_prioritizes_rule29_categories(self):
        cases = checklist_for("wstg")
        plan = next_open_items("wstg", cases, {}, set(), "high_impact")
        # first item is a high-value category, and pure-manual items are dropped
        self.assertIn(plan[0]["category"], ("ATHZ", "ATHN", "INPV", "BUSL", "APIT", "SESS"))
        self.assertTrue(all("manual" not in c["tool"].lower() for c in plan))


if __name__ == "__main__":
    unittest.main()
