"""target_brief — one-call situational orientation (Spec E recon-intel map)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from burpsuite_mcp.tools.intel.brief import build_brief


class TargetBriefTest(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def _seed(self, domain, **files):
        d = Path(f".burp-intel/{domain}")
        d.mkdir(parents=True)
        for name, obj in files.items():
            (d / f"{name}.json").write_text(json.dumps(obj))
        return d

    def test_new_target_returns_recon_directive(self):
        b = build_brief("fresh.test")
        self.assertFalse(b["exists"])
        self.assertIn("recon", b["directive"].lower())

    def test_context_and_posture_fused(self):
        self._seed(
            "x.test",
            profile={"tech_stack": ["nginx", "next.js"], "auth_model": "oauth"},
            endpoints={"endpoints": [{"url": "/a"}, {"url": "/b"}, {"url": "/c"}]},
            coverage={"entries": [{"e": "/a", "class": "xss"}], "knowledge_version": 7},
            findings={"findings": [
                {"id": "F1", "title": "SQLi", "severity": "high", "status": "confirmed",
                 "endpoint": "/a", "poc_request": "x" * 999},
                {"id": "F2", "title": "XSS", "severity": "low", "status": "suspected",
                 "endpoint": "/b"},
            ]},
        )
        b = build_brief("x.test")
        self.assertTrue(b["exists"])
        self.assertEqual(b["context"]["tech_stack"], ["nginx", "next.js"])
        self.assertEqual(b["context"]["auth_model"], "oauth")
        self.assertEqual(b["posture"]["endpoints_known"], 3)
        self.assertEqual(b["posture"]["coverage_tuples"], 1)
        self.assertEqual(b["posture"]["findings"]["confirmed"], 1)
        self.assertEqual(b["posture"]["findings"]["total"], 2)

    def test_top_findings_severity_ranked_and_lean(self):
        self._seed("x.test", findings={"findings": [
            {"id": "F2", "title": "low", "severity": "low", "status": "suspected",
             "endpoint": "/b", "evidence": {"blob": "y" * 5000}},
            {"id": "F1", "title": "crit", "severity": "critical", "status": "confirmed",
             "endpoint": "/a", "poc_request": "z" * 5000},
        ]})
        b = build_brief("x.test")
        self.assertEqual(b["top_findings"][0]["id"], "F1")  # critical first
        self.assertNotIn("poc_request", b["top_findings"][0])
        self.assertNotIn("evidence", b["top_findings"][1])

    def test_next_actions_reflect_state(self):
        self._seed("x.test",
                   endpoints={"endpoints": [{"url": "/a"}, {"url": "/b"}]},
                   coverage={"entries": []},
                   findings={"findings": [
                       {"id": "F1", "title": "x", "severity": "high",
                        "status": "suspected", "endpoint": "/a"}]})
        actions = " ".join(build_brief("x.test")["next_actions"])
        self.assertIn("verify", actions.lower())
        self.assertIn("coverage gap", actions.lower())

    def test_quick_queries_are_field_projected(self):
        self._seed("x.test", findings={"findings": []})
        q = build_brief("x.test")["quick_queries"][0]
        self.assertIn("fields=", q)
        self.assertIn("x.test", q)


if __name__ == "__main__":
    unittest.main()
