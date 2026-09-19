"""OCR-driven sensitive-span detection for auto-redaction (pure logic)."""

import unittest

from praetor.tools._redact_ocr import (
    _is_sensitive_value,
    _merge_boxes,
    _sensitive_boxes,
    _trailing_fraction,
)


def _w(text, left, line="1-1-1", top=100, width=None, height=14):
    return {"text": text, "left": left, "top": top,
            "width": width if width is not None else len(text) * 7,
            "height": height, "line": line}


class ValueShapeTest(unittest.TestCase):
    def test_secret_shapes_flagged(self):
        self.assertTrue(_is_sensitive_value("25d7a7ce75eecfbf324c49b2bfcb01bc"))   # hex
        self.assertTrue(_is_sensitive_value("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))  # JWT
        self.assertTrue(_is_sensitive_value("user@example.com"))                  # email

    def test_benign_not_flagged(self):
        # base64-ish MIME/header values must NOT be flagged standalone (false-positive
        # source) — only after a key. Only high-precision shapes are standalone.
        for t in ("login.php", "GET", "id=1", "Host", "text/html",
                  "application/xhtml+xml,", "image/webp,"):
            self.assertFalse(_is_sensitive_value(t), t)


class SensitiveBoxesTest(unittest.TestCase):
    def test_cookie_line_redacts_value_not_label(self):
        words = [_w("Cookie:", 50), _w("security=low;", 130),
                 _w("PHPSESSID=25d7a7ce75eecfbf324c49b2bfcb01bc", 300)]
        boxes = _sensitive_boxes(words)
        self.assertTrue(boxes)
        # nothing boxed starts at the "Cookie:" label position (x=50)
        self.assertTrue(all(b[0] > 60 for b in boxes), boxes)

    def test_plain_header_line_untouched(self):
        self.assertEqual(_sensitive_boxes([_w("Host:", 50), _w("pentest-ground.com", 120)]), [])

    def test_standalone_token_redacted(self):
        boxes = _sensitive_boxes([_w("marker", 50), _w("25d7a7ce75eecfbf324c49b2bfcb01bc", 130)])
        self.assertEqual(len(boxes), 1)

    def test_authorization_bearer_redacted(self):
        words = [_w("Authorization:", 50), _w("Bearer", 200), _w("eyJhbGciOiJIUzI1NiJ9", 270)]
        self.assertTrue(_sensitive_boxes(words))


class TrailingFractionTest(unittest.TestCase):
    def test_covers_back_half_keeps_prefix(self):
        # value box x=100 w=200 -> back half is x=200 w=100 (prefix 100..200 stays)
        self.assertEqual(_trailing_fraction([[100, 50, 200, 18]], 0.5), [[200, 50, 100, 18]])

    def test_full_coverage_unchanged(self):
        self.assertEqual(_trailing_fraction([[100, 50, 200, 18]], 1.0), [[100, 50, 200, 18]])

    def test_never_zero_width(self):
        # tiny box still yields at least 1px so a short value isn't left uncovered
        self.assertTrue(all(b[2] >= 1 for b in _trailing_fraction([[10, 5, 3, 18]], 0.5)))


class MergeBoxesTest(unittest.TestCase):
    def test_merges_adjacent_on_same_line(self):
        self.assertEqual(len(_merge_boxes([[100, 50, 30, 14], [135, 50, 40, 14]])), 1)

    def test_keeps_different_lines_separate(self):
        self.assertEqual(len(_merge_boxes([[100, 50, 30, 14], [100, 100, 30, 14]])), 2)

    def test_empty(self):
        self.assertEqual(_merge_boxes([]), [])


if __name__ == "__main__":
    unittest.main()
