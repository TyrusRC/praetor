"""Red call-out box around Burp's yellow search highlight (pure logic)."""

import unittest

from praetor.tools._highlight_box import cluster_points, is_highlight


class IsHighlightTest(unittest.TestCase):
    def test_burp_yellow(self):
        self.assertTrue(is_highlight(240, 240, 90))   # sampled Burp highlight
        self.assertTrue(is_highlight(250, 245, 100))

    def test_white_not_highlight(self):
        self.assertFalse(is_highlight(255, 255, 255))

    def test_orange_syntax_not_highlight(self):
        self.assertFalse(is_highlight(250, 150, 50))   # R>>G

    def test_dark_text_not_highlight(self):
        self.assertFalse(is_highlight(30, 30, 30))

    def test_scrollbar_marker_not_highlight(self):
        # Burp's scrollbar match-markers are pure yellow (B=0) — must be excluded
        self.assertFalse(is_highlight(255, 255, 0))

    def test_pale_chrome_not_highlight(self):
        self.assertFalse(is_highlight(255, 222, 156))   # tab underline / search accent


class ClusterPointsTest(unittest.TestCase):
    def test_single_line_one_box(self):
        # a highlighted line spans the glyph height (~24px), not one scan row
        pts = [(100, 44), (140, 60), (180, 52), (220, 68)]
        boxes = cluster_points(pts)
        self.assertEqual(len(boxes), 1)
        x, y, w, h = boxes[0]
        self.assertEqual(x, 100)
        self.assertEqual(w, 120)

    def test_two_far_lines_two_boxes(self):
        pts = [(100, 44), (150, 66), (100, 400), (150, 422)]
        self.assertEqual(len(cluster_points(pts)), 2)

    def test_tiny_stray_dropped(self):
        # a 2x2 fleck of yellow (an icon) is below min size
        self.assertEqual(cluster_points([(10, 10), (11, 11)]), [])

    def test_empty(self):
        self.assertEqual(cluster_points([]), [])


if __name__ == "__main__":
    unittest.main()
