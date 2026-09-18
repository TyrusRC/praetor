"""attach_screenshot: link a saved PNG to a finding's evidence.screenshots."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools.notes._screenshot_attach import _attach_screenshot


class AttachScreenshotTest(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)
        self.addCleanup(os.chdir, self._cwd)
        self.domain = "example.com"
        self.dom_dir = Path(".burp-intel") / self.domain
        (self.dom_dir / "screenshots").mkdir(parents=True)
        self._shot("burp-repeater-x.png")
        self._write_findings([{"id": "f001", "title": "IDOR", "evidence": {"logger_index": 5}}])

    def _shot(self, name):
        (self.dom_dir / "screenshots" / name).write_bytes(b"\x89PNG-body")

    def _write_findings(self, findings):
        (self.dom_dir / "findings.json").write_text(json.dumps({"findings": findings}))

    def _read_finding(self, fid):
        data = json.loads((self.dom_dir / "findings.json").read_text())
        return next(f for f in data["findings"] if f["id"] == fid)

    def test_appends_relative_ref_and_note(self):
        out = _attach_screenshot(self.domain, "f001", "burp-repeater-x.png", "swap id=2")
        self.assertTrue(out.get("ok"))
        self.assertEqual(out["file"], "screenshots/burp-repeater-x.png")
        shots = self._read_finding("f001")["evidence"]["screenshots"]
        self.assertEqual(shots, [{"file": "screenshots/burp-repeater-x.png", "note": "swap id=2"}])

    def test_accepts_full_saved_path(self):
        full = str(self.dom_dir / "screenshots" / "burp-repeater-x.png")
        out = _attach_screenshot(self.domain, "f001", full, "")
        self.assertTrue(out.get("ok"))

    def test_stores_step_for_ordering(self):
        out = _attach_screenshot(self.domain, "f001", "burp-repeater-x.png", "attack", step="2-attack")
        self.assertEqual(out["step"], "2-attack")
        shots = self._read_finding("f001")["evidence"]["screenshots"]
        self.assertEqual(shots[0], {"file": "screenshots/burp-repeater-x.png",
                                    "note": "attack", "step": "2-attack"})

    def test_idempotent_updates_note_not_duplicates(self):
        _attach_screenshot(self.domain, "f001", "burp-repeater-x.png", "first")
        _attach_screenshot(self.domain, "f001", "burp-repeater-x.png", "second")
        shots = self._read_finding("f001")["evidence"]["screenshots"]
        self.assertEqual(len(shots), 1)
        self.assertEqual(shots[0]["note"], "second")

    def test_missing_screenshot_file_errors(self):
        out = _attach_screenshot(self.domain, "f001", "nope.png", "")
        self.assertIn("error", out)

    def test_non_image_errors(self):
        out = _attach_screenshot(self.domain, "f001", "burp-repeater-x.txt", "")
        self.assertIn("error", out)

    def test_unknown_finding_errors(self):
        out = _attach_screenshot(self.domain, "f404", "burp-repeater-x.png", "")
        self.assertIn("error", out)

    def test_save_and_attach_agree_on_hostport_domain(self):
        # HIGH regression: _save_shot and _attach_screenshot must resolve the SAME
        # dir for a domain that _sanitized rewrites (host:port), else the shot is
        # written but not found on attach.
        import base64
        from praetor.tools.burp_ui import _save_shot
        dom = "example.com:8080"
        sdir = Path(".burp-intel") / "example.com_8080"
        (sdir / "screenshots").mkdir(parents=True)
        (sdir / "findings.json").write_text(json.dumps({"findings": [{"id": "f9", "evidence": {}}]}))
        out = _save_shot({"png_base64": base64.b64encode(b"\x89PNG").decode()},
                         dom, "logger", "n", finding_id="f9")
        self.assertIn("example.com_8080", out["saved"])
        att = _attach_screenshot(dom, "f9", out["saved"], "n")
        self.assertTrue(att.get("ok"), att)

    def test_additive_on_locked_finding(self):
        # A locked finding freezes its verdict, but adding evidence is allowed.
        self._write_findings([{"id": "f002", "title": "SQLi", "locked": True,
                               "status": "confirmed", "severity": "HIGH", "evidence": {}}])
        out = _attach_screenshot(self.domain, "f002", "burp-repeater-x.png", "proof")
        self.assertTrue(out.get("ok"))
        f = self._read_finding("f002")
        self.assertTrue(f["locked"])            # verdict untouched
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(len(f["evidence"]["screenshots"]), 1)


if __name__ == "__main__":
    unittest.main()
