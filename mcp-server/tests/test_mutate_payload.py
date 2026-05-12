"""Calibration tests for mutate_payload + fuzz_with_feedback.

Pure stdlib (unittest + asyncio). Run with:
    uv run python -m unittest tests.test_mutate_payload -v
"""

import asyncio
import unittest
from unittest.mock import patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.mutate import generate_variants


class MutatePayloadTests(unittest.TestCase):
    def test_default_classes_produce_distinct_variants(self):
        out = generate_variants("' OR 1=1--")
        self.assertGreater(len(out), 5)
        variants = [v["variant"] for v in out]
        self.assertEqual(len(variants), len(set(variants)))
        self.assertNotIn("' OR 1=1--", variants)

    def test_url_encode_class(self):
        out = generate_variants("alert(1)", classes=["encoding_url"])
        self.assertTrue(any("%61%6c%65%72%74" in v["variant"] for v in out))

    def test_case_toggle_class(self):
        out = generate_variants("SELECT", classes=["case_toggle"])
        self.assertEqual(out[0]["variant"], "select")

    def test_sql_comment_class(self):
        out = generate_variants("UNION SELECT", classes=["comment_sql"])
        joined = " ".join(v["variant"] for v in out)
        self.assertIn("/**/", joined)

    def test_null_byte_class(self):
        out = generate_variants("../etc/passwd", classes=["null_byte"])
        prefixes = [v["variant"] for v in out if v["mutator"] == "null_prefix"]
        suffixes = [v["variant"] for v in out if v["mutator"] == "null_suffix"]
        self.assertTrue(prefixes and prefixes[0].startswith("%00"))
        self.assertTrue(suffixes and suffixes[0].endswith("%00"))

    def test_whitespace_alt_class(self):
        out = generate_variants("UNION SELECT", classes=["whitespace_alt"])
        variants = [v["variant"] for v in out]
        self.assertIn("UNION\tSELECT", variants)
        self.assertIn("UNION+SELECT", variants)
        self.assertIn("UNION%09SELECT", variants)
        self.assertIn("UNION%0cSELECT", variants)

    def test_quote_rotate_class(self):
        out = generate_variants("admin'--", classes=["quote_rotate"])
        joined = " ".join(v["variant"] for v in out)
        self.assertIn('admin"--', joined)
        self.assertIn("admin`--", joined)

    def test_count_cap_respected(self):
        out = generate_variants("payload", count=3)
        self.assertEqual(len(out), 3)

    def test_empty_seed_returns_empty(self):
        self.assertEqual(generate_variants(""), [])

    def test_unknown_class_is_ignored_not_error(self):
        out = generate_variants("test", classes=["bogus_class", "case_toggle"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["mutation_class"], "case_toggle")

    def test_html_entity_class(self):
        out = generate_variants("<x>", classes=["encoding_html"])
        variants = [v["variant"] for v in out]
        self.assertIn("&#60;&#120;&#62;", variants)
        self.assertIn("&#x3c;&#x78;&#x3e;", variants)

    def test_unicode_escape_class(self):
        out = generate_variants("ab", classes=["encoding_unicode"])
        self.assertEqual(out[0]["variant"], "\\u0061\\u0062")


class FuzzWithFeedbackTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = staticmethod(server.mcp._tool_manager._tools["fuzz_with_feedback"].fn)

    async def test_signal_match_stops_early(self):
        baseline = {"status": 200, "body": "ok", "headers": {}, "_elapsed_ms": 50}
        hit_body = "SQL syntax error near '?'"
        hit = {"status": 500, "body": hit_body, "headers": {}, "_elapsed_ms": 60}

        call_count = {"n": 0}

        async def fake_post(path, json=None):
            call_count["n"] += 1
            # First call is baseline; rest are probes. Hit appears at call 3.
            if call_count["n"] == 1:
                return dict(baseline)
            if call_count["n"] == 3:
                return dict(hit)
            return dict(baseline)

        with patch("burpsuite_mcp.tools.testing.fuzz_feedback.client.post", fake_post):
            out = await self.tool(
                url="https://example.com/q",
                parameter="q",
                seed="' OR 1=1--",
                signals={"regex": "SQL syntax", "status_in": [500]},
                max_iters=20,
                early_stop=True,
                concurrency=1,
            )
        self.assertIn("Hits:", out)
        self.assertIn("SQL syntax", out)

    async def test_no_hits_reports_top3(self):
        async def fake_post(path, json=None):
            return {"status": 200, "body": "ok", "headers": {}, "_elapsed_ms": 50}

        with patch("burpsuite_mcp.tools.testing.fuzz_feedback.client.post", fake_post):
            out = await self.tool(
                url="https://example.com/q",
                parameter="q",
                seed="test",
                signals={"regex": "should-not-match-anything"},
                max_iters=5,
                early_stop=False,
                concurrency=1,
            )
        self.assertIn("No variants matched", out)
        self.assertIn("Top-3", out)

    async def test_baseline_error_returns_error(self):
        async def fake_post(path, json=None):
            return {"error": "Connection refused"}

        with patch("burpsuite_mcp.tools.testing.fuzz_feedback.client.post", fake_post):
            out = await self.tool(
                url="https://example.com/q",
                parameter="q",
                seed="test",
                signals={"regex": "x"},
                max_iters=5,
            )
        self.assertIn("Error sending baseline", out)

    async def test_empty_seed_rejected(self):
        out = await self.tool(
            url="https://example.com/q",
            parameter="q",
            seed="",
            signals={"regex": "x"},
        )
        self.assertIn("seed payload is required", out)

    async def test_missing_signals_rejected(self):
        out = await self.tool(
            url="https://example.com/q",
            parameter="q",
            seed="payload",
            signals={},
        )
        self.assertIn("signals dict is required", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
