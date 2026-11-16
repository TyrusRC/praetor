"""Cross-request canary engine (mint_canary / scan_for_stored_canaries) —
gap found reviewing CyberStrike's Vortex canary.ts: confirm_second_order
needs a (store_endpoint, trigger_endpoint) pair named in advance. A token
minted once and scanned for across every later response catches a stored
injection whose trigger the operator never thought to pair up.
"""

from __future__ import annotations

import shutil
import unittest
from unittest.mock import AsyncMock, patch

from praetor import client, server
from praetor.tools.exploit import _canary_store
from praetor.tools.notes._helpers import _intel_dir, _sanitized

_DOMAIN = "canary-engine-test.example.com"


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class CanaryEngineTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        shutil.rmtree(_intel_dir() / _sanitized(_DOMAIN), ignore_errors=True)

    def tearDown(self):
        shutil.rmtree(_intel_dir() / _sanitized(_DOMAIN), ignore_errors=True)

    async def test_mint_returns_a_token_and_records_it(self):
        fn = _tool("mint_canary")
        token = await fn(domain=_DOMAIN, endpoint="https://t/profile",
                         parameter="bio", vuln_class="stored_xss", origin_index=10)
        self.assertTrue(token.startswith("cnry-"))
        store = _canary_store.load(_DOMAIN)
        self.assertIn(token, store)
        self.assertEqual(store[token]["origin_endpoint"], "https://t/profile")
        self.assertEqual(store[token]["origin_index"], 10)
        self.assertFalse(store[token]["resolved"])

    async def test_scan_excludes_the_origin_index_reports_only_other_hits(self):
        mint = _tool("mint_canary")
        scan = _tool("scan_for_stored_canaries")
        token = await mint(domain=_DOMAIN, endpoint="https://t/profile",
                           parameter="bio", vuln_class="stored_xss", origin_index=10)

        async def fake_post(path, json=None):
            self.assertEqual(path, "/api/search/history")
            self.assertEqual(json["query"], token)
            self.assertTrue(json["in_response_body"])
            return {"results": [
                {"index": 10, "method": "POST", "status_code": 200, "url": "https://t/profile"},
                {"index": 77, "method": "GET", "status_code": 200, "url": "https://t/admin/users/5"},
            ]}

        with patch.object(client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await scan(domain=_DOMAIN)

        hit_lines = [l.strip() for l in out.splitlines() if l.strip().startswith("idx=")]
        self.assertEqual(hit_lines, ["idx=77 GET 200 https://t/admin/users/5"],
                         "origin index must never appear as a reported stored hit")
        self.assertIn("confirm_second_order", out)

    async def test_resolved_token_is_not_re_reported(self):
        mint = _tool("mint_canary")
        scan = _tool("scan_for_stored_canaries")
        token = await mint(domain=_DOMAIN, endpoint="https://t/profile",
                           parameter="bio", origin_index=10)

        async def fake_post_hit(path, json=None):
            return {"results": [{"index": 77, "method": "GET", "status_code": 200, "url": "https://t/x"}]}

        with patch.object(client, "post", new=AsyncMock(side_effect=fake_post_hit)):
            first = await scan(domain=_DOMAIN)
        self.assertIn("idx=77", first)

        store = _canary_store.load(_DOMAIN)
        self.assertTrue(store[token]["resolved"], "a found hit must mark the token resolved")

        second = await scan(domain=_DOMAIN)
        self.assertIn("no unresolved canaries", second)

    async def test_no_hit_leaves_token_pending_for_a_later_scan(self):
        mint = _tool("mint_canary")
        scan = _tool("scan_for_stored_canaries")
        await mint(domain=_DOMAIN, endpoint="https://t/profile", parameter="bio")

        async def fake_post_empty(path, json=None):
            return {"results": []}

        with patch.object(client, "post", new=AsyncMock(side_effect=fake_post_empty)):
            out = await scan(domain=_DOMAIN)
        self.assertIn("no canary resurfaced elsewhere yet", out)

        store = _canary_store.load(_DOMAIN)
        self.assertEqual(len(store), 1)
        self.assertFalse(next(iter(store.values()))["resolved"])

    async def test_list_canaries_shows_pending_and_resolved(self):
        mint = _tool("mint_canary")
        listc = _tool("list_canaries")
        await mint(domain=_DOMAIN, endpoint="https://t/a", parameter="p1")
        out = await listc(domain=_DOMAIN)
        self.assertIn("pending", out)
        self.assertIn("1 token(s)", out)


if __name__ == "__main__":
    unittest.main()
