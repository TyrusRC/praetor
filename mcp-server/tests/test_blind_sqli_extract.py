"""Unit tests for blind_sqli_extract's extraction math and oracle eval.

The binary search is the part that can silently return a wrong password, so
it is tested directly against a fake oracle that answers `X > m` for a known
value X — no network. Cond builders and oracle interpretation are pinned too.
"""

import asyncio
import unittest

from praetor.tools.exploit import blind_sqli_extract as B


def _gt_oracle(true_value: int):
    """Fake is_true: parses the trailing `>m` and answers true_value > m."""
    async def is_true(cond: str) -> bool:
        m = int(cond.rsplit(">", 1)[1])
        return true_value > m
    return is_true


class ExtractionMath(unittest.TestCase):
    def test_length_binary_search(self):
        for real in (1, 20, 63, 64):
            got = asyncio.run(B._discover_length(_gt_oracle(real), "oracle", "password", 64))
            self.assertEqual(got, real, f"length {real}")

    def test_char_binary_search_spans_charset(self):
        # digits, letters, and both charset edges (space=32, ~=126)
        for ch in "a5z09q ~m":
            got = asyncio.run(
                B._extract_char(_gt_oracle(ord(ch)), "oracle", "password", 1, 32, 126))
            self.assertEqual(got, ch, f"char {ch!r}")

    def test_cond_builders_are_dbms_aware(self):
        self.assertEqual(B._char_cond("oracle", "password", 2, 100),
                         "ASCII(SUBSTR(password,2,1))>100")
        self.assertEqual(B._char_cond("postgres", "password", 2, 100),
                         "ASCII(SUBSTRING(password,2,1))>100")
        self.assertEqual(B._char_cond("sqlite", "password", 1, 50),
                         "UNICODE(SUBSTR(password,1,1))>50")
        self.assertEqual(B._length_cond("mssql", "password", 5), "LEN(password)>5")
        self.assertEqual(B._length_cond("mysql", "password", 5), "LENGTH(password)>5")


class OracleEval(unittest.TestCase):
    def test_status_oracle(self):
        spec = {"type": "status", "true_status": 500}
        self.assertTrue(B._eval_oracle(spec, {"status_code": 500}))
        self.assertFalse(B._eval_oracle(spec, {"status_code": 200}))

    def test_content_true_marker(self):
        spec = {"type": "content", "true_marker": "Welcome back"}
        self.assertTrue(B._eval_oracle(spec, {"response_body": "...Welcome back..."}))
        self.assertFalse(B._eval_oracle(spec, {"response_body": "nope"}))

    def test_content_false_marker_inverts(self):
        spec = {"type": "content", "false_marker": "Welcome back"}
        self.assertFalse(B._eval_oracle(spec, {"response_body": "Welcome back"}))
        self.assertTrue(B._eval_oracle(spec, {"response_body": "nope"}))

    def test_bad_oracle_raises(self):
        with self.assertRaises(ValueError):
            B._eval_oracle({"type": "bogus"}, {"status_code": 200})


if __name__ == "__main__":
    unittest.main()
