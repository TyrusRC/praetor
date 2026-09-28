"""sync_workspace reconciles derived .burp-intel files against findings.json."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from praetor.tools.notes.reconcile import reconcile


class ReconcileTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="recon-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)
        self.dom = self.tmp / ".burp-intel" / "t.example"
        (self.dom / "findings").mkdir(parents=True)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_findings(self, findings):
        (self.dom / "findings.json").write_text(json.dumps({"findings": findings}))

    def test_regenerates_projection_and_reports_clean(self):
        self._write_findings([{
            "id": "f001", "title": "SQLi in id", "endpoint": "https://t.example/x",
            "vuln_type": "sqli", "severity": "high", "impact": "DB read",
            "evidence": {"proxy_history_index": 5}, "status": "confirmed",
        }])
        r = reconcile("t.example", fix=True)
        self.assertTrue(r["in_sync"])
        self.assertEqual(r["projections_regenerated"], 1)
        self.assertTrue((self.dom / "findings" / "f001" / "current.md").exists())

    def test_removes_orphan_writeup(self):
        self._write_findings([{"id": "f001", "title": "x", "endpoint": "https://t/x",
                               "vuln_type": "sqli", "severity": "low",
                               "evidence": {"proxy_history_index": 1}}])
        (self.dom / "findings" / "f999").mkdir()            # orphan (no such finding)
        (self.dom / "findings" / "f999" / "current.md").write_text("stale")
        r = reconcile("t.example", fix=True)
        self.assertIn("f999", r["orphans_removed"])
        self.assertFalse((self.dom / "findings" / "f999").exists())

    def test_flags_duplicate_missing_evidence_and_no_impact(self):
        self._write_findings([
            {"id": "f001", "title": "dup", "endpoint": "https://t/x", "vuln_type": "xss",
             "parameter": "q", "severity": "low", "evidence": {"proxy_history_index": 1}},
            {"id": "f002", "title": "dup", "endpoint": "https://t/x", "vuln_type": "xss",
             "parameter": "q", "severity": "low", "evidence": {"proxy_history_index": 2}},
            {"id": "f003", "title": "no ev", "endpoint": "https://t/y", "vuln_type": "idor",
             "severity": "high", "impact": "x", "evidence": {}},
            {"id": "f004", "title": "no impact", "endpoint": "https://t/z", "vuln_type": "ssrf",
             "severity": "critical", "impact": "", "evidence": {"proxy_history_index": 3}},
        ])
        drift = " ".join(reconcile("t.example", fix=True)["drift"])
        self.assertIn("DUPLICATE", drift)
        self.assertIn("NO EVIDENCE", drift)
        self.assertIn("NO IMPACT", drift)
        self.assertIn("f004", drift)

    def test_flags_stale_checkpoint_reference(self):
        self._write_findings([{"id": "f001", "title": "x", "endpoint": "https://t/x",
                               "vuln_type": "sqli", "severity": "low",
                               "evidence": {"proxy_history_index": 1}}])
        (self.dom / "checkpoint.json").write_text(json.dumps(
            {"next_action": "verify finding f042"}))
        drift = " ".join(reconcile("t.example", fix=True)["drift"])
        self.assertIn("STALE CHECKPOINT", drift)
        self.assertIn("f042", drift)

    def test_dry_run_does_not_remove(self):
        self._write_findings([{"id": "f001", "title": "x", "endpoint": "https://t/x",
                               "vuln_type": "sqli", "severity": "low",
                               "evidence": {"proxy_history_index": 1}}])
        (self.dom / "findings" / "f999").mkdir()
        r = reconcile("t.example", fix=False)
        self.assertIn("f999", r["orphans_found"])
        self.assertEqual(r["orphans_removed"], [])
        self.assertTrue((self.dom / "findings" / "f999").exists())   # not removed


if __name__ == "__main__":
    unittest.main()
