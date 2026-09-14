"""concurrent_requests must not follow redirects by default.

The server (CurlSender) follows redirects when `follow_redirects` is absent,
which collapses a 3xx into the redirected 200 and hides the exact signal this
tool exists to surface — a 429 for rate-limit testing, a 302 for a brute-force
success. Regression guard: the tool pins follow_redirects=False per request
unless the caller overrides it in the request dict.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools.send import _concurrent


def _get_tool():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    _concurrent.register(_Stub())
    return captured["concurrent_requests"]


class ConcurrentRedirectDefaultTest(unittest.TestCase):

    def _run(self, requests):
        tool = _get_tool()
        sent: list[dict] = []

        async def fake_post(path, json=None):
            sent.append(json)
            return {"status_code": 302, "response_body": "",
                    "response_headers": [], "history_index": len(sent)}

        # apply_realistic_headers is exercised for real; only the wire is mocked.
        with patch.object(_concurrent.client, "post",
                          new=AsyncMock(side_effect=fake_post)):
            asyncio.run(tool(requests, concurrency=1))
        return sent

    def test_default_is_no_follow(self):
        sent = self._run([
            {"method": "POST", "url": "https://t.example/login", "data": "x=1"},
        ])
        self.assertEqual(len(sent), 1)
        self.assertIs(sent[0]["follow_redirects"], False)

    def test_caller_override_wins(self):
        sent = self._run([
            {"method": "GET", "url": "https://t.example/a",
             "follow_redirects": True},
        ])
        self.assertIs(sent[0]["follow_redirects"], True)

    def test_applies_to_every_request(self):
        sent = self._run([
            {"method": "GET", "url": "https://t.example/a"},
            {"method": "GET", "url": "https://t.example/b"},
            {"method": "GET", "url": "https://t.example/c"},
        ])
        self.assertEqual(len(sent), 3)
        self.assertTrue(all(s["follow_redirects"] is False for s in sent))


if __name__ == "__main__":
    unittest.main()
