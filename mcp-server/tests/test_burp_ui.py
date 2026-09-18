"""burp_screenshot save-helper: decode the extension's base64 PNG to disk."""

import base64
import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools.burp_ui import _save_shot


class SaveShotTest(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)
        self.addCleanup(os.chdir, self._cwd)

    def test_writes_png_under_domain_screenshots_dir(self):
        raw = b"\x89PNG\r\n\x1a\n-fake-body"
        data = {"png_base64": base64.b64encode(raw).decode(),
                "width": 1920, "height": 1080, "title": "Burp Suite"}
        out = _save_shot(data, "example.com", "repeater", "IDOR PoC")

        self.assertNotIn("error", out)
        p = Path(out["saved"])
        self.assertTrue(p.exists())
        self.assertEqual(p.read_bytes(), raw)
        # domain dir + tab label in the filename; feeds screenshot_gallery.
        self.assertIn(str(Path(".burp-intel") / "example.com" / "screenshots"), out["saved"])
        self.assertTrue(p.name.startswith("burp-repeater-"))
        self.assertEqual(out["width"], 1920)
        self.assertEqual(out["note"], "IDOR PoC")

    def test_empty_domain_falls_back_to_burp_bucket(self):
        data = {"png_base64": base64.b64encode(b"x").decode()}
        out = _save_shot(data, "", "", "")
        self.assertIn(str(Path(".burp-intel") / "_burp" / "screenshots"), out["saved"])
        self.assertTrue(Path(out["saved"]).name.startswith("burp-suite-"))

    def test_missing_image_is_an_error(self):
        self.assertIn("error", _save_shot({"width": 10}, "d", "", ""))

    def test_bad_base64_is_an_error(self):
        out = _save_shot({"png_base64": "not!valid!base64!"}, "d", "", "")
        self.assertIn("error", out)

    def test_tab_slashes_sanitized_in_filename(self):
        data = {"png_base64": base64.b64encode(b"x").decode()}
        out = _save_shot(data, "d", "proxy/http history", "")
        self.assertTrue(Path(out["saved"]).name.startswith("burp-proxy-http-history-"))

    def test_filename_describes_the_evidence(self):
        # tab + finding id + caption slug all land in the name so it self-documents.
        data = {"png_base64": base64.b64encode(b"x").decode()}
        out = _save_shot(data, "d", "repeater", "IDOR order id=2", finding_id="f001")
        name = Path(out["saved"]).name
        self.assertTrue(name.startswith("burp-repeater-f001-idor-order-id-2-"))
        self.assertTrue(name.endswith(".png"))
        self.assertEqual(out["finding_id"], "f001")

    def test_step_in_filename_and_envelope(self):
        data = {"png_base64": base64.b64encode(b"x").decode()}
        out = _save_shot(data, "d", "logger", "SQLi error", finding_id="f001", step="2-attack")
        name = Path(out["saved"]).name
        self.assertTrue(name.startswith("burp-logger-f001-step-2-attack-sqli-error-"))
        self.assertEqual(out["step"], "2-attack")

    def test_same_second_captures_do_not_overwrite(self):
        # microsecond ts: two identical-param captures in one second stay distinct.
        data = {"png_base64": base64.b64encode(b"x").decode()}
        o1 = _save_shot(data, "d", "logger", "same", finding_id="f1")
        o2 = _save_shot(data, "d", "logger", "same", finding_id="f1")
        self.assertNotEqual(o1["saved"], o2["saved"])
        self.assertTrue(Path(o1["saved"]).exists())
        self.assertTrue(Path(o2["saved"]).exists())

    def test_traversal_domain_returns_error(self):
        data = {"png_base64": base64.b64encode(b"x").decode()}
        out = _save_shot(data, "../../etc", "logger", "")
        self.assertIn("error", out)

    def test_caption_builds_step_and_note(self):
        from praetor.tools.burp_ui import _caption
        self.assertEqual(_caption("2-attack", "SQLi payload"), "Step 2-attack — SQLi payload")
        self.assertEqual(_caption("1", ""), "Step 1")
        self.assertEqual(_caption("", "just a note"), "just a note")
        self.assertEqual(_caption("", ""), "")


if __name__ == "__main__":
    unittest.main()
