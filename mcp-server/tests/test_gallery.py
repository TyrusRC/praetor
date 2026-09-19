"""Screenshot gallery — offline visual-triage contact sheet.

Pure render coverage. No Burp client, no network.
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestGallery(unittest.TestCase):
    def setUp(self):
        from praetor.tools.gallery import render_gallery_html
        self.render = render_gallery_html

    def test_one_card_per_shot(self):
        html = self.render(
            "example.com",
            [
                {"file": "2026-01-01T00-00-00.png", "note": "login page"},
                {"file": "2026-01-01T00-01-00.png", "note": ""},
            ],
        )
        self.assertEqual(html.count("<img"), 2)
        self.assertIn("login page", html)

    def test_img_src_is_relative_to_screenshots(self):
        html = self.render("example.com", [{"file": "a.png", "note": ""}])
        self.assertIn('src="../screenshots/a.png"', html)

    def test_empty_gallery_renders_placeholder(self):
        html = self.render("example.com", [])
        self.assertIn("<html", html.lower())
        self.assertIn("no screenshots", html.lower())

    def test_note_is_html_escaped(self):
        html = self.render("x", [{"file": "a.png", "note": "<script>x</script>"}])
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestVisibleShots(unittest.TestCase):
    def setUp(self):
        from praetor.tools.gallery import _notes_from_findings, _visible_shots
        self.visible = _visible_shots
        self.notes = _notes_from_findings

    def test_hides_naked_partner_of_redacted_twin(self):
        names = ["burp-x.png", "burp-x-redacted.png", "browser-y.png"]
        # the raw burp-x.png is dropped; the redacted twin and the lone shot stay
        self.assertEqual(self.visible(names), ["burp-x-redacted.png", "browser-y.png"])

    def test_lone_shot_without_twin_is_kept(self):
        self.assertEqual(self.visible(["only.png"]), ["only.png"])

    def test_redacted_without_naked_is_kept(self):
        self.assertEqual(self.visible(["a-redacted.png"]), ["a-redacted.png"])

    def test_notes_missing_file_is_empty(self):
        self.assertEqual(self.notes(Path("/nonexistent/findings.json")), {})


if __name__ == "__main__":
    unittest.main()
