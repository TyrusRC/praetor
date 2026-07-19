import os
import tempfile
import unittest
from pathlib import Path

from burpsuite_mcp.tools.notes._projection import (
    render_finding_md, write_finding_projection, remove_finding_projection)

FINDING = {
    "id": "VULN-001", "title": "Reflected XSS in q", "severity": "medium",
    "status": "confirmed", "endpoint": "https://x.test/search", "parameter": "q",
    "evidence": {"logger_index": 42},
    "reproductions": [{"logger_index": 42, "status_code": 200}],
    "poc_steps": ["GET /search?q=<script>...", "observe alert"], "chain_with": [],
}


class TestProjection(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_render_contains_core_fields(self):
        md = render_finding_md(FINDING)
        self.assertIn("VULN-001", md)
        self.assertIn("medium", md)
        self.assertIn("/search", md)
        self.assertIn("logger_index", md)

    def test_write_creates_current_md(self):
        write_finding_projection("x.test", FINDING)
        cur = Path(".burp-intel/x.test/findings/VULN-001/current.md")
        self.assertTrue(cur.exists())
        self.assertIn("Reflected XSS", cur.read_text())

    def test_remove_deletes_folder(self):
        write_finding_projection("x.test", FINDING)
        remove_finding_projection("x.test", "VULN-001")
        self.assertFalse(Path(".burp-intel/x.test/findings/VULN-001").exists())

    def test_hard_delete_removes_projection(self):
        # Exercises the wired delete path in _helpers._hard_delete_finding.
        import asyncio
        from burpsuite_mcp.tools.notes._helpers import (
            _safe_findings_path, _write_findings_file, _hard_delete_finding)
        rec = dict(FINDING)
        path = _safe_findings_path("x.test")
        _write_findings_file(path, {"findings": [rec], "last_modified": ""})
        write_finding_projection("x.test", rec)
        self.assertTrue(Path(".burp-intel/x.test/findings/VULN-001").exists())
        asyncio.run(_hard_delete_finding("x.test", rec))
        self.assertFalse(Path(".burp-intel/x.test/findings/VULN-001").exists())

    def test_record_retest_versions(self):
        from burpsuite_mcp.tools.notes._helpers import (
            _safe_findings_path, _write_findings_file, _load_findings_file)
        from burpsuite_mcp.tools.notes.retest import _apply_retest
        path = _safe_findings_path("x.test")
        _write_findings_file(path, {"findings": [dict(FINDING)], "last_modified": ""})
        _apply_retest("x.test", "VULN-001", "reopened", "2026-09-01", "", "still vuln")
        _apply_retest("x.test", "VULN-001", "fixed", "2026-10-15", "", "patched")
        store = _load_findings_file(path)
        rt = store["findings"][0]["retests"]
        self.assertEqual([r["version"] for r in rt], [1, 2])
        self.assertTrue(Path(".burp-intel/x.test/findings/VULN-001/v1_2026-09-01_reopened.md").exists())
        self.assertTrue(Path(".burp-intel/x.test/findings/VULN-001/v2_2026-10-15_fixed.md").exists())

    def test_record_retest_bad_status(self):
        from burpsuite_mcp.tools.notes._helpers import _safe_findings_path, _write_findings_file
        from burpsuite_mcp.tools.notes.retest import _apply_retest
        _write_findings_file(_safe_findings_path("x.test"),
                             {"findings": [dict(FINDING)], "last_modified": ""})
        with self.assertRaises(ValueError):
            _apply_retest("x.test", "VULN-001", "bogus", "2026-09-01", "", "")


if __name__ == "__main__":
    unittest.main()
