"""send_raw_request(count>1) aggregates an N-shot desync loop into a histogram.

Motivation: request-smuggling capture/queue-poison attacks fire the same
byte-exact request many times to catch an intermittent victim on a poisoned
back-end connection. Before this, the only way to loop was a raw-socket script
that bypassed Burp (no Logger entry, against Rule 26a). The summary must make
the 200/302/400 split legible at a glance and surface captured redirect
Locations (the 302 -> confirmation that signals a stored comment).
"""

from __future__ import annotations

import unittest
from collections import Counter

from praetor.tools.send._send import _format_repeat_summary


class RawRepeatSummaryTest(unittest.TestCase):

    def test_histogram_sorted_by_frequency(self):
        codes = Counter({200: 43, 302: 40, 400: 37})
        out = _format_repeat_summary(120, "direct", codes, Counter(), Counter())
        self.assertIn("x120", out)
        self.assertIn("http_version=direct", out)
        # Most frequent code appears before less frequent ones.
        self.assertLess(out.index("200:43"), out.index("400:37"))

    def test_locations_surfaced(self):
        locs = Counter({"/post/comment/confirmation?postId=1": 40})
        out = _format_repeat_summary(80, "direct", Counter({302: 40}), locs, Counter())
        self.assertIn("Redirect Location(s):", out)
        self.assertIn("40x /post/comment/confirmation?postId=1", out)

    def test_errors_surfaced(self):
        out = _format_repeat_summary(
            10, "direct", Counter({200: 8}), Counter(), Counter({"timeout": 2}))
        self.assertIn("Errors: timeout (2)", out)

    def test_auto_label_when_no_version(self):
        out = _format_repeat_summary(3, "", Counter({200: 3}), Counter(), Counter())
        self.assertIn("http_version=auto", out)

    def test_logger_note_always_present(self):
        out = _format_repeat_summary(2, "direct", Counter({200: 2}), Counter(), Counter())
        self.assertIn("Burp Logger", out)


if __name__ == "__main__":
    unittest.main()
