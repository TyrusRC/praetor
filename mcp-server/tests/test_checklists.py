"""Detailed per-test-case checklists (OWASP AI Testing Guide seeded)."""

import unittest

from praetor.tools.assurance._checklists import (
    checklist_for,
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


class RenderChecklistTest(unittest.TestCase):
    def test_renders_items_and_open_count(self):
        cases = checklist_for("ai_testing")
        out = render_checklist("ai_testing", "OWASP AI Testing Guide", cases, set())
        self.assertIn("AITG-APP-01", out)
        self.assertIn("32 test cases still OPEN", out)  # nothing touched
        self.assertIn("-> ", out)  # tool mapping shown

    def test_touched_category_marks_items(self):
        cases = checklist_for("ai_testing")
        out = render_checklist("ai_testing", "OWASP AI Testing Guide", cases, {"APP"})
        # 14 APP items become touched -> 32-14 = 18 open
        self.assertIn("18/32 test cases still OPEN", out)
        self.assertIn("## APP (touched)", out)


if __name__ == "__main__":
    unittest.main()
