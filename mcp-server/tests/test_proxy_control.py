"""Proxy control helpers: annotation validation, finding lookup, dangerous headers.

Pure stdlib — no Burp, no async. Run with:
    uv run python -m unittest tests.test_proxy_control -v
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from praetor.tools.proxy_control._helpers import (
    _DANGEROUS_HEADER_PATTERNS,
    _lookup_finding_id,
    _record_annotation_on_finding,
)


class DangerousHeaderPatterns(unittest.TestCase):

    def test_host_is_flagged(self):
        self.assertTrue(any("host:" in p for p in _DANGEROUS_HEADER_PATTERNS))

    def test_authorization_is_flagged(self):
        self.assertTrue(any("authorization:" in p for p in _DANGEROUS_HEADER_PATTERNS))

    def test_cookie_is_flagged(self):
        self.assertTrue(any("cookie:" in p for p in _DANGEROUS_HEADER_PATTERNS))

    def test_content_length_is_flagged(self):
        self.assertTrue(any("content-length:" in p for p in _DANGEROUS_HEADER_PATTERNS))

    def test_transfer_encoding_is_flagged(self):
        self.assertTrue(any("transfer-encoding:" in p for p in _DANGEROUS_HEADER_PATTERNS))


class FindingLookup(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="burp-intel-test-"))
        self.origcwd = Path.cwd()
        os.chdir(self.tmpdir)
        # Create a fake .burp-intel/<domain>/findings.json
        domain_dir = self.tmpdir / ".burp-intel" / "test.example.com"
        domain_dir.mkdir(parents=True)
        findings = {
            "findings": [
                {"id": "f001", "title": "SQL Injection on /search",
                 "status": "confirmed"},
                {"id": "f002", "title": "XSS on /profile",
                 "status": "confirmed"},
            ]
        }
        (domain_dir / "findings.json").write_text(
            json.dumps(findings), encoding="utf-8")

    def tearDown(self):
        os.chdir(self.origcwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_existing_id(self):
        exists, desc = _lookup_finding_id("f001")
        self.assertTrue(exists)
        self.assertIn("test.example.com", desc)
        self.assertIn("SQL Injection", desc)

    def test_finds_second_id(self):
        exists, desc = _lookup_finding_id("f002")
        self.assertTrue(exists)
        self.assertIn("XSS", desc)

    def test_missing_id_returns_false(self):
        exists, desc = _lookup_finding_id("f999")
        self.assertFalse(exists)

    def test_empty_id_returns_false(self):
        exists, _ = _lookup_finding_id("")
        self.assertFalse(exists)


class AnnotationRecording(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="burp-intel-test-"))
        self.origcwd = Path.cwd()
        os.chdir(self.tmpdir)
        domain_dir = self.tmpdir / ".burp-intel" / "test.example.com"
        domain_dir.mkdir(parents=True)
        findings = {
            "findings": [
                {"id": "f001", "title": "SQLi", "status": "confirmed"},
            ]
        }
        self.findings_path = domain_dir / "findings.json"
        self.findings_path.write_text(
            json.dumps(findings), encoding="utf-8")

    def tearDown(self):
        os.chdir(self.origcwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_annotation_appended_to_finding(self):
        tag = {"index": 42, "color": "RED", "notes": "f001 | sqli | UNION match"}
        _record_annotation_on_finding("f001", tag)
        data = json.loads(self.findings_path.read_text(encoding="utf-8"))
        finding = data["findings"][0]
        self.assertEqual(len(finding["annotations"]), 1)
        self.assertEqual(finding["annotations"][0]["index"], 42)

    def test_same_index_replaces_not_stacks(self):
        tag1 = {"index": 10, "color": "ORANGE", "notes": "first"}
        tag2 = {"index": 10, "color": "RED", "notes": "second"}
        _record_annotation_on_finding("f001", tag1)
        _record_annotation_on_finding("f001", tag2)
        data = json.loads(self.findings_path.read_text(encoding="utf-8"))
        anns = data["findings"][0]["annotations"]
        self.assertEqual(len(anns), 1, "same index should replace, not stack")
        self.assertEqual(anns[0]["notes"], "second")

    def test_different_indices_accumulate(self):
        _record_annotation_on_finding("f001", {"index": 10, "color": "RED"})
        _record_annotation_on_finding("f001", {"index": 20, "color": "ORANGE"})
        data = json.loads(self.findings_path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"][0]["annotations"]), 2)

    def test_nonexistent_finding_no_crash(self):
        _record_annotation_on_finding("f999", {"index": 1, "color": "RED"})
        # Should not raise — best-effort


if __name__ == "__main__":
    unittest.main()
