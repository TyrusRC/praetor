"""burp_screenshot row selection: reach a specific request by identity, not by a
Praetor evidence index (which is NOT Burp's "#" column value — the bug the Mac
operator hit when select_row landed on unrelated traffic)."""

import asyncio
import unittest
from unittest.mock import patch

from praetor.tools import burp_ui


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class SelectRowByIdentityTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        burp_ui.register(self.mcp)
        self.calls = []

    def _run(self, **kw):
        async def fake_get(path, params=None):
            self.calls.append((path, params or {}))
            if path.startswith("/api/proxy/history/"):
                return {"method": "GET",
                        "url": "https://accounts.example.com/oidc/callback?code=abc"}
            return {"error": "headless"}   # skip _save_shot; params already captured
        with patch.object(burp_ui.client, "get", fake_get):
            asyncio.run(self.mcp.tools["burp_screenshot"](**kw))
        for path, params in self.calls:
            if path == "/api/ui/screenshot":
                return params
        return {}

    def test_select_url_becomes_text_needle(self):
        params = self._run(select_url="oidc/callback")
        self.assertEqual(params.get("select_match"), "oidc/callback")
        # a URL substring must NOT trigger a history lookup
        self.assertFalse(any(p.startswith("/api/proxy/history/") for p, _ in self.calls))

    def test_proxy_index_resolves_to_host_and_path(self):
        params = self._run(select_proxy_index=42)
        # server looked the index up and matched by host+path (AND), not "#42" —
        # host pins the request when a path repeats across hosts.
        self.assertIn(("/api/proxy/history/42", {}), self.calls)
        self.assertEqual(params.get("select_match"),
                         "accounts.example.com /oidc/callback")

    def test_select_url_wins_over_index(self):
        params = self._run(select_url="wanted", select_proxy_index=42)
        self.assertEqual(params.get("select_match"), "wanted")
        self.assertFalse(any(p.startswith("/api/proxy/history/") for p, _ in self.calls))

    def test_numeric_select_row_sets_no_match(self):
        params = self._run(select_row="last")
        self.assertEqual(params.get("select_row"), "last")
        self.assertNotIn("select_match", params)


if __name__ == "__main__":
    unittest.main()
