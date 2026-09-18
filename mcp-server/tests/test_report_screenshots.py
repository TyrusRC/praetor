"""Screenshots render as deliverable evidence (client-safe) in a finding section."""

import unittest

from praetor.tools.report._evidence_fmt import extract_screenshots
from praetor.tools.report._finding_render import build_finding_section


def _finding():
    return {
        "title": "IDOR on /api/orders",
        "severity": "HIGH",
        "endpoint": "https://example.com/api/orders/2",
        "evidence": {
            "logger_index": 42,  # internal, stripped from client
            "screenshots": [
                {"file": "screenshots/burp-repeater-x.png", "note": "id=2 -> victim order"},
            ],
        },
    }


class ExtractScreenshotsTest(unittest.TestCase):
    def test_normalises_list_and_legacy_scalar(self):
        ev = {"screenshots": [{"file": "screenshots/a.png", "note": "n"}, "screenshots/b.png"],
              "screenshot": "screenshots/c.png"}
        got = extract_screenshots(ev)
        files = [s["file"] for s in got]
        self.assertEqual(files, ["screenshots/a.png", "screenshots/b.png", "screenshots/c.png"])

    def test_non_dict_is_empty(self):
        self.assertEqual(extract_screenshots("nope"), [])


class RenderScreenshotTest(unittest.TestCase):
    def test_client_report_shows_basename_only(self):
        out = build_finding_section(_finding(), 1, internal=False)
        self.assertIn("Screenshot: `burp-repeater-x.png`", out)
        self.assertIn("id=2 -> victim order", out)
        # No internal path leaked, and the Burp index is stripped for the client.
        self.assertNotIn(".burp-intel", out)
        self.assertNotIn("screenshots/burp-repeater-x.png", out)
        self.assertNotIn("logger_index", out)

    def test_internal_report_keeps_relative_path(self):
        out = build_finding_section(_finding(), 1, internal=True)
        self.assertIn("Screenshot: `screenshots/burp-repeater-x.png`", out)
        self.assertIn("logger_index", out)  # internal keeps bookkeeping


if __name__ == "__main__":
    unittest.main()
