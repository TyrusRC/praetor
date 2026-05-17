"""Calibration tests for analyze_reset_tokens.

Tests the entropy / sequential / timestamp-correlation detectors directly
on the inner helpers so the suite stays pure-compute.

Run: uv run python -m unittest tests.test_reset_tokens -v
"""

import time
import unittest

from burpsuite_mcp.tools.auth.reset_tokens import (
    _detect_sequential,
    _detect_timestamp,
    _looks_b64,
    _looks_hex,
    _shannon_entropy,
    _total_entropy_bits,
)


class ShapeDetectionTests(unittest.TestCase):
    def test_looks_hex_true(self):
        self.assertTrue(_looks_hex("0123456789abcdef"))
        self.assertTrue(_looks_hex("ABCDEF"))

    def test_looks_hex_false(self):
        self.assertFalse(_looks_hex(""))
        self.assertFalse(_looks_hex("abc-def"))
        self.assertFalse(_looks_hex("xyz"))

    def test_looks_b64_true(self):
        self.assertTrue(_looks_b64("abcDEF123+/="))
        self.assertTrue(_looks_b64("hello-_world"))

    def test_looks_b64_false_short(self):
        self.assertFalse(_looks_b64("ab"))

    def test_looks_b64_false_bad_chars(self):
        self.assertFalse(_looks_b64("hello world"))


class ShannonEntropyTests(unittest.TestCase):
    def test_empty_string_zero(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_uniform_string_zero(self):
        # All same char -> entropy 0.
        self.assertEqual(_shannon_entropy("aaaa"), 0.0)

    def test_hex_random_near_4_bits(self):
        # A reasonably uniform 32-hex string scores close to log2(16) = 4
        # per character.
        e = _shannon_entropy("0123456789abcdef0123456789abcdef")
        self.assertGreater(e, 3.5)
        self.assertLessEqual(e, 4.0)

    def test_total_entropy_scales_with_length(self):
        e_short = _total_entropy_bits("abab")
        e_long = _total_entropy_bits("abab" * 4)
        self.assertGreater(e_long, e_short)


class SequentialDetectionTests(unittest.TestCase):
    def test_pure_sequential_decimal(self):
        tokens = ["reset_1001", "reset_1002", "reset_1003", "reset_1004"]
        is_seq, reason = _detect_sequential(tokens)
        self.assertTrue(is_seq)
        self.assertIn("reset_", reason)

    def test_pure_sequential_hex(self):
        tokens = ["tk_000001", "tk_000002", "tk_000003"]
        is_seq, _ = _detect_sequential(tokens)
        self.assertTrue(is_seq)

    def test_random_tokens_not_sequential(self):
        tokens = ["a3f4d7b8", "9c2e1f4a", "b7d2c0e1", "44ab19fe"]
        is_seq, _ = _detect_sequential(tokens)
        self.assertFalse(is_seq)

    def test_mixed_length_not_sequential(self):
        tokens = ["abc", "abcd"]
        is_seq, reason = _detect_sequential(tokens)
        self.assertFalse(is_seq)
        self.assertIn("length", reason)

    def test_single_token_not_sequential(self):
        is_seq, _ = _detect_sequential(["only"])
        self.assertFalse(is_seq)

    def test_descending_not_flagged(self):
        # Only ascending sequential is flagged — descending is rare in real
        # token generators and would false-positive on shuffle.
        tokens = ["tk_005", "tk_004", "tk_003"]
        is_seq, _ = _detect_sequential(tokens)
        self.assertFalse(is_seq)

    def test_jittered_increment_still_flagged(self):
        # +1, +2, +1 — within 50% of mean. Counts as sequential.
        tokens = ["t_100", "t_101", "t_103", "t_104"]
        is_seq, _ = _detect_sequential(tokens)
        self.assertTrue(is_seq)

    def test_wildly_varying_delta_not_sequential(self):
        # 1, 200, 5 — deltas too uneven.
        tokens = ["t_001", "t_201", "t_206"]
        is_seq, _ = _detect_sequential(tokens)
        self.assertFalse(is_seq)


class TimestampDetectionTests(unittest.TestCase):
    def test_no_capture_times_returns_false(self):
        ok, _ = _detect_timestamp(["a", "b"], None)
        self.assertFalse(ok)

    def test_mismatched_lengths_returns_false(self):
        ok, _ = _detect_timestamp(["a"], [1.0, 2.0])
        self.assertFalse(ok)

    def test_hex_timestamp_prefix_detected(self):
        # Token = hex(unix_time)[:8] + random_suffix. Three tokens captured
        # 60s apart should correlate.
        now = int(time.time())
        tokens = [
            f"{now:08x}" + "deadbeef",
            f"{now + 60:08x}" + "cafe1234",
            f"{now + 120:08x}" + "abcd9876",
        ]
        capture_times = [float(now), float(now + 60), float(now + 120)]
        ok, reason = _detect_timestamp(tokens, capture_times)
        self.assertTrue(ok)
        self.assertIn("8", reason)

    def test_random_hex_not_flagged_as_timestamp(self):
        tokens = ["a3f4d7b8" + "cafe1234",
                  "9c2e1f4a" + "deadbeef",
                  "b7d2c0e1" + "11112222"]
        # Capture times in ascending order shouldn't matter — tokens are random.
        now = time.time()
        capture_times = [now, now + 60, now + 120]
        ok, _ = _detect_timestamp(tokens, capture_times)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
