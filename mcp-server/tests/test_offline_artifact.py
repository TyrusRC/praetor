import unittest

from praetor.tools.offline import _report


class TestReportHelpers(unittest.TestCase):
    def test_redact_shows_only_shape(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        red = _report.redact_secret(secret)
        self.assertNotIn(secret, red)
        self.assertTrue(red.startswith("AKIA"))
        self.assertTrue(red.endswith("MPLE"))
        self.assertIn("…", red)

    def test_redact_short_value_fully_masked(self):
        self.assertEqual(_report.redact_secret("abc"), "…")

    def test_confine_path_rejects_traversal(self):
        root = "/home/kali/project/trc/praetor/mcp-server/tests/fixtures/offline"
        self.assertIsNone(_report.confine_path(root, root + "/../../../etc/passwd"))

    def test_assemble_fills_missing_keys(self):
        out = _report.assemble("js", "app.js", {"secrets": [{"type": "aws"}]})
        self.assertEqual(out["kind"], "js")
        self.assertEqual(out["source"], "app.js")
        self.assertEqual(out["secrets"], [{"type": "aws"}])
        for k in ("attack_surface", "api_inventory", "inputs", "id_references",
                  "sources_sinks", "observations", "hypotheses", "priority_test_plan"):
            self.assertEqual(out[k], [])
