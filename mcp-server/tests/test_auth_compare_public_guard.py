"""Dual-baseline public-data FP guard for compare_auth_states (2026-07-25).

The #1 IDOR false positive: two authed states return identical data, so the
tool flags IDOR — but the resource is actually PUBLIC (returns the same with no
auth). A third unauthenticated probe must downgrade that to FAILED.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class AuthComparePublicGuard(unittest.IsolatedAsyncioTestCase):

    def _register(self):
        from praetor.tools.testing import auth_compare
        stub, captured = _stub_mcp()
        auth_compare.register(stub)
        return auth_compare, captured["compare_auth_states"]

    async def test_public_resource_suppressed(self):
        mod, fn = self._register()

        async def fake_post(path, json=None):
            mh = (json or {}).get("modify_headers", {})
            cookie = mh.get("Cookie", "MISSING")
            if cookie == "":                       # request 3 — unauthenticated
                return {"status_code": 200, "response_length": 100, "response_body": "PUBLIC"}
            # request 1 (user A) and request 2 (user B) — both see the same data
            return {"status_code": 200, "response_length": 100, "response_body": "PUBLIC"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            out = await fn(index=1, original_cookies={"s": "A"}, alt_cookies={"s": "B"})

        self.assertEqual(out["verdict"], "FAILED")
        self.assertTrue(out["details"]["public_resource"])
        self.assertIn("PUBLIC", out["evidence_summary"].upper())

    async def test_real_idor_not_suppressed(self):
        mod, fn = self._register()

        async def fake_post(path, json=None):
            mh = (json or {}).get("modify_headers", {})
            cookie = mh.get("Cookie", "MISSING")
            if cookie == "":                       # request 3 — unauth is REJECTED
                return {"status_code": 401, "response_length": 12, "response_body": "denied"}
            # both authed users see the private resource → genuine IDOR
            return {"status_code": 200, "response_length": 200, "response_body": "SECRET-DATA"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            out = await fn(index=1, original_cookies={"s": "A"}, alt_cookies={"s": "B"})

        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertFalse(out["details"]["public_resource"])

    async def test_check_public_disabled(self):
        mod, fn = self._register()
        calls = {"n": 0}

        async def fake_post(path, json=None):
            calls["n"] += 1
            return {"status_code": 200, "response_length": 100, "response_body": "SAME"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            out = await fn(index=1, original_cookies={"s": "A"}, alt_cookies={"s": "B"},
                           check_public=False)

        # Only 2 requests (no third unauth probe); verdict stays CONFIRMED.
        self.assertEqual(calls["n"], 2)
        self.assertEqual(out["verdict"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
