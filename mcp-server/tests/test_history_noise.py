"""Proxy-history noise classifier + HTTPQL integration — drop the CDN/ads/telemetry
flood so a lookup returns the target's app traffic and costs a fraction of tokens."""

import asyncio
import unittest
from unittest.mock import patch

from praetor.tools import httpql
from praetor.tools.read._noise import classify, is_noise


class ClassifyTest(unittest.TestCase):
    def test_analytics_ads_telemetry_hosts(self):
        self.assertEqual(classify("https://www.google-analytics.com/collect"), "analytics")
        self.assertEqual(classify("https://securepubads.g.doubleclick.net/x"), "ads")
        self.assertEqual(classify("https://optimizationguide-pa.googleapis.com/v1"), "telemetry")

    def test_static_media_is_asset_but_code_is_signal(self):
        self.assertEqual(classify("https://acme.tld/logo.png"), "asset")
        self.assertEqual(classify("https://acme.tld/f.woff2"), "asset")
        # JS / CSS / JSON / maps carry endpoints + secrets -> never noise
        self.assertEqual(classify("https://acme.tld/app.js"), "")
        self.assertEqual(classify("https://acme.tld/main.css"), "")
        self.assertEqual(classify("https://acme.tld/api/users.json"), "")

    def test_mime_fallback(self):
        self.assertEqual(classify("https://acme.tld/img?id=1", "image/png"), "asset")
        self.assertEqual(classify("https://acme.tld/api/users", "application/json"), "")

    def test_target_app_and_api_are_signal(self):
        self.assertEqual(classify("https://acme.tld/oidc/callback?code=abc"), "")
        self.assertFalse(is_noise({"url": "https://acme.tld/api/v1/orders"}))
        self.assertTrue(is_noise({"url": "https://www.googletagmanager.com/gtm.js"}))

    def test_browser_extension_backends_are_noise(self):
        # Grammarly & co fire from every page the operator visits — not the target
        self.assertEqual(classify("https://gnar.grammarly.com/log"), "extension")
        self.assertEqual(classify("https://api.languagetool.org/v2/check"), "extension")
        self.assertTrue(is_noise({"url": "https://d.joinhoney.com/track"}))
        # but a target that genuinely IS one of these hosts is out of this list's
        # remit — scope is the real filter; the classifier stays conservative


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


_HISTORY = {
    "items": [
        {"index": 1, "method": "GET", "url": "https://acme.tld/oidc/callback",
         "status_code": 302, "response_length": 0, "mime_type": "text/html"},
        {"index": 2, "method": "GET", "url": "https://www.google-analytics.com/collect",
         "status_code": 200, "response_length": 35, "mime_type": "text/plain"},
        {"index": 3, "method": "GET", "url": "https://acme.tld/logo.png",
         "status_code": 200, "response_length": 9000, "mime_type": "image/png"},
        {"index": 4, "method": "POST", "url": "https://acme.tld/api/v1/orders",
         "status_code": 200, "response_length": 512, "mime_type": "application/json"},
    ]
}


class QueryDslNoiseTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        httpql.register(self.mcp)

    def _run(self, **kw):
        async def fake_get(path, params=None):
            return _HISTORY
        with patch.object(httpql.client, "get", fake_get):
            return asyncio.run(self.mcp.tools["query_history_dsl"](**kw))

    def test_noise_dropped_by_default(self):
        out = self._run(query="host = acme.tld")
        self.assertIn("/oidc/callback", out)
        self.assertIn("/api/v1/orders", out)
        self.assertNotIn("google-analytics", out)   # analytics dropped
        self.assertNotIn("logo.png", out)            # asset dropped
        self.assertIn("hid 2 noise rows", out)

    def test_drop_noise_false_keeps_everything(self):
        out = self._run(query="host = acme.tld", drop_noise=False)
        # the acme rows still match host filter; analytics is a different host
        self.assertIn("logo.png", out)

    def test_noise_field_inspects_dropped(self):
        out = self._run(query="noise = true")
        self.assertIn("google-analytics", out)
        self.assertIn("logo.png", out)
        self.assertNotIn("/api/v1/orders", out)      # signal excluded by noise=true

    def test_noise_query_disables_auto_drop(self):
        # an explicit noise clause owns the decision -> no "hid N" footer
        out = self._run(query="noise = false")
        self.assertNotIn("hid ", out)
        self.assertIn("/oidc/callback", out)

    def test_scope_wins_targeting_an_extension_host(self):
        # classifier: an explicitly-kept host is never noise even if on the list
        self.assertEqual(classify("https://gnar.grammarly.com/log",
                                  keep_hosts=("grammarly.com",)), "")
        self.assertFalse(is_noise({"url": "https://gnar.grammarly.com/log"},
                                  keep_hosts=("grammarly.com",)))


class KeepHostQueryTest(QueryDslNoiseTest):
    def test_filtering_on_extension_host_keeps_it(self):
        hist = {"items": [
            {"index": 1, "method": "GET", "url": "https://gnar.grammarly.com/log",
             "status_code": 200, "response_length": 10, "mime_type": "text/plain"},
        ]}

        async def fake_get(path, params=None):
            return hist
        with patch.object(httpql.client, "get", fake_get):
            out = asyncio.run(self.mcp.tools["query_history_dsl"](query="host ~ grammarly.com"))
        # targeting grammarly on purpose -> not dropped
        self.assertIn("grammarly.com", out)
        self.assertNotIn("hid 1", out)


if __name__ == "__main__":
    unittest.main()
