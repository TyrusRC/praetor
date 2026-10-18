"""confirm_exposed_sourcemap — fetch + confirm a leaked source map (Acunetix-
parity: detecting the sourceMappingURL reference alone was already covered by
smart_js_analyze; this is the missing CONFIRMATION step)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from praetor.tools.exploit.confirm_exposed_sourcemap import register


class _ToolCapture:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _map_body(sources=None, contents=None):
    d = {"version": 3, "sources": sources or [], "mappings": "AAAA"}
    if contents is not None:
        d["sourcesContent"] = contents
    return json.dumps(d)


class ConfirmExposedSourcemapTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        cap = _ToolCapture()
        register(cap)
        self.confirm = cap.tools["confirm_exposed_sourcemap"]

    def _patched(self, responses):
        """responses: dict url -> response dict (as /api/resources/fetch would return)."""
        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            return responses.get(url, {"error": f"unmocked url {url}"})
        return patch("praetor.client.post", fake_post)

    async def test_no_args_is_error(self):
        v = await self.confirm()
        self.assertEqual(v["verdict"], "ERROR")

    async def test_map_404_is_failed(self):
        with self._patched({"https://t/x.map": {"status_code": 404, "content": "not found", "index": 1}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "FAILED")

    async def test_soft_404_html_is_failed_not_confirmed(self):
        with self._patched({"https://t/x.map": {"status_code": 200, "content": "<html>login</html>", "index": 1}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "FAILED")
        self.assertIn("not valid source-map JSON", v["evidence_summary"])

    async def test_exposed_with_paths_only_is_weak_suspected(self):
        body = _map_body(sources=["webpack:///./src/app.js"])
        with self._patched({"https://t/x.map": {"status_code": 200, "content": body, "index": 1}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "SUSPECTED")
        self.assertEqual(v["confidence"], 0.2)
        self.assertIn("informational alone", v["evidence_summary"])

    async def test_exposed_with_sourcescontent_no_secret_is_suspected(self):
        body = _map_body(sources=["app.ts"], contents=["export const x = 1;"])
        with self._patched({"https://t/x.map": {"status_code": 200, "content": body, "index": 1}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "SUSPECTED")
        self.assertEqual(v["confidence"], 0.45)

    async def test_exposed_with_embedded_secret_is_confirmed(self):
        # Built at runtime, never as one literal substring in this source file —
        # GitHub's secret scanner pattern-matches file CONTENTS, and a fake key
        # this shape still trips it even with "FAKE" in the text (confirmed live).
        leaked = "sk_live_" + "FAKEEXAMPLE" * 3 + "123456"
        body = _map_body(sources=["config.ts"], contents=[f'const stripeKey = "{leaked}";'])
        with self._patched({"https://t/x.map": {"status_code": 200, "content": body, "index": 7}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "CONFIRMED")
        self.assertEqual(v["confidence"], 0.9)
        hit = v["details"]["secret_hits"][0]
        self.assertEqual(hit["type"], "stripe_live_secret")
        self.assertNotIn(leaked, json.dumps(v))  # never echo the real value, only its shape
        self.assertEqual(v["logger_indices"], [7])

    async def test_js_url_extracts_sourcemappingurl_and_resolves_relative(self):
        js = "console.log(1);\n//# sourceMappingURL=app.js.map"
        body = _map_body(sources=["app.ts"])
        with self._patched({
            "https://t/static/app.js": {"status_code": 200, "content": js},
            "https://t/static/app.js.map": {"status_code": 200, "content": body, "index": 2},
        }):
            v = await self.confirm(js_url="https://t/static/app.js")
        self.assertEqual(v["verdict"], "SUSPECTED")  # paths-only
        self.assertEqual(v["details"]["map_url"], "https://t/static/app.js.map")

    async def test_js_url_with_no_reference_is_failed(self):
        with self._patched({"https://t/static/app.js": {"status_code": 200, "content": "console.log(1);"}}):
            v = await self.confirm(js_url="https://t/static/app.js")
        self.assertEqual(v["verdict"], "FAILED")
        self.assertIn("no sourceMappingURL reference", v["evidence_summary"])

    async def test_network_failure_is_error_not_crash(self):
        async def fail_post(path, json=None):
            return {"error": "connection refused"}
        with patch("praetor.client.post", fail_post):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertEqual(v["verdict"], "ERROR")

    async def test_haruspex_off_leaves_verdict_intact(self):
        # decision engine unconfigured in the test env -> enrich_with_haruspex
        # must fail open and still return a well-formed verdict (no "haruspex" key).
        body = _map_body(sources=["app.ts"])
        with self._patched({"https://t/x.map": {"status_code": 200, "content": body, "index": 1}}):
            v = await self.confirm(map_url="https://t/x.map")
        self.assertIn("verdict", v)
        self.assertNotIn("haruspex", v)


if __name__ == "__main__":
    unittest.main()
