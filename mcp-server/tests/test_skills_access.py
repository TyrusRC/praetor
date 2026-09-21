"""Skill-access pure helpers — the cross-host list/get seam (skills_access.py)."""

import unittest

from praetor.tools.skills_access import _description, read_skill, skill_entries


class DescriptionTest(unittest.TestCase):
    def test_extracts_frontmatter_description(self):
        text = "---\nname: x\ndescription: Do the thing quickly\n---\n# X\n"
        self.assertEqual(_description(text), "Do the thing quickly")

    def test_missing_description_is_empty(self):
        self.assertEqual(_description("# no frontmatter\nbody"), "")


class SkillEntriesTest(unittest.TestCase):
    def test_lists_known_skills_with_descriptions(self):
        entries = skill_entries()
        names = {e["name"] for e in entries}
        # Skills that exist in the repo — a real regression if one vanishes silently.
        self.assertIn("lab-solve", names)
        self.assertIn("chain-findings", names)
        # every entry has both keys; sorted by name
        self.assertTrue(all("name" in e and "description" in e for e in entries))
        self.assertEqual([e["name"] for e in entries],
                         sorted(e["name"] for e in entries))
        lab = next(e for e in entries if e["name"] == "lab-solve")
        self.assertIn("single-objective", lab["description"].lower())


class ReadSkillTest(unittest.TestCase):
    def test_reads_full_markdown(self):
        got = read_skill("lab-solve")
        self.assertEqual(got["name"], "lab-solve")
        self.assertIn("single-objective", got["markdown"].lower())

    def test_unknown_skill_returns_error_and_available(self):
        got = read_skill("does-not-exist")
        self.assertIn("error", got)
        self.assertIn("lab-solve", got["available"])

    def test_path_traversal_rejected(self):
        for bad in ("../rules/hunting", "..\\rules\\hunting", "a/b"):
            self.assertEqual(read_skill(bad).get("error"), "invalid skill name")


if __name__ == "__main__":
    unittest.main()
