"""W25-b — probe_passkey_stepup_bypass (CVE-2026-32879)."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class PasskeyStepupBypassErrorPathsTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_auth_returns_error(self):
        fn = _tool("probe_passkey_stepup_bypass")
        out = await fn(stepup_url="https://t/api/stepup")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("bearer_token or cookies", out["evidence_summary"])

    async def test_no_stepup_url_returns_error(self):
        fn = _tool("probe_passkey_stepup_bypass")
        out = await fn(stepup_url="", bearer_token="abc")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_scope_reject_returns_error(self):
        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": False})):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(stepup_url="https://oos/api/stepup", bearer_token="abc")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("not in scope", out["evidence_summary"])


class PasskeyStepupBypassVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_verified_marker_and_protected_open_confirmed(self):
        """Canonical CVE-2026-32879 path: server returns verified-marker on
        bogus body, AND protected endpoint subsequently returns 200."""
        responses = iter([
            # 3 step-up probes (canonical + 2 variants) — all return verified marker
            {"status_code": 200, "proxy_index": 10,
             "response_body": '{"verified":true}', "response_headers": []},
            {"status_code": 200, "proxy_index": 11,
             "response_body": '{"verified":true}', "response_headers": []},
            {"status_code": 200, "proxy_index": 12,
             "response_body": '{"verified":true}', "response_headers": []},
            # protected endpoint GET
            {"status_code": 200, "proxy_index": 13,
             "response_body": '{"secret":"channel_secret_abc123"}',
             "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(
                stepup_url="https://t/api/stepup",
                protected_url="https://t/api/channel/1/key",
                bearer_token="session-abc",
            )
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertGreaterEqual(out["confidence"], 0.90)
        self.assertEqual(out["details"]["verified_hits"], 3)
        self.assertTrue(out["details"]["protected_confirmed"])
        # All 4 logger indices captured
        self.assertEqual(sorted(out["logger_indices"]), [10, 11, 12, 13])

    async def test_verified_marker_only_no_protected_url_confirmed_lower(self):
        """When operator does NOT supply protected_url, marker-only confirmation
        still CONFIRMS but at lower confidence (0.80 vs 0.95)."""
        responses = iter([
            {"status_code": 200, "proxy_index": 20,
             "response_body": "secure_verification_token=xxx", "response_headers": []},
            {"status_code": 200, "proxy_index": 21,
             "response_body": "ok", "response_headers": []},
            {"status_code": 200, "proxy_index": 22,
             "response_body": "ok", "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(stepup_url="https://t/api/stepup",
                           bearer_token="session-abc")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["confidence"], 0.80)
        self.assertGreaterEqual(out["details"]["verified_hits"], 1)

    async def test_verified_marker_but_protected_403_suspected(self):
        """Marker present but protected endpoint still gated — partial bypass /
        decorative marker. SUSPECTED, not CONFIRMED."""
        responses = iter([
            {"status_code": 200, "proxy_index": 30,
             "response_body": '{"verified":true}', "response_headers": []},
            {"status_code": 200, "proxy_index": 31,
             "response_body": '{"verified":true}', "response_headers": []},
            {"status_code": 200, "proxy_index": 32,
             "response_body": '{"verified":true}', "response_headers": []},
            # protected endpoint refuses despite step-up marker
            {"status_code": 403, "proxy_index": 33,
             "response_body": '{"error":"stepup_required"}',
             "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(
                stepup_url="https://t/api/stepup",
                protected_url="https://t/api/channel/1/key",
                bearer_token="session-abc",
            )
        self.assertEqual(out["verdict"], "SUSPECTED")
        self.assertEqual(out["details"]["protected_status"], 403)
        self.assertFalse(out["details"]["protected_confirmed"])

    async def test_assertion_required_failed(self):
        """Server returns invalid_credential/assertion_required markers —
        correctly enforces WebAuthn → FAILED."""
        responses = iter([
            {"status_code": 400, "proxy_index": 40,
             "response_body": '{"error":"assertion_required"}',
             "response_headers": []},
            {"status_code": 400, "proxy_index": 41,
             "response_body": '{"error":"invalid_credential"}',
             "response_headers": []},
            {"status_code": 400, "proxy_index": 42,
             "response_body": '{"error":"challenge_required"}',
             "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(stepup_url="https://t/api/stepup",
                           bearer_token="session-abc")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertGreaterEqual(out["details"]["assertion_required_hits"], 1)

    async def test_ambiguous_no_marker_failed(self):
        """No verified-marker AND no assertion-required marker → still FAILED
        (server didn't accept the bypass body)."""
        responses = iter([
            {"status_code": 200, "proxy_index": 50,
             "response_body": "<html>some unrelated page</html>",
             "response_headers": []},
            {"status_code": 200, "proxy_index": 51,
             "response_body": "ok", "response_headers": []},
            {"status_code": 200, "proxy_index": 52,
             "response_body": "ok", "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(stepup_url="https://t/api/stepup",
                           bearer_token="session-abc")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["verified_hits"], 0)

    async def test_extra_variants_false_fires_one_body(self):
        """extra_variants=False sends only the canonical body."""
        responses = iter([
            {"status_code": 200, "proxy_index": 60,
             "response_body": "ok", "response_headers": []},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.passkey_stepup.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.auth.passkey_stepup.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_passkey_stepup_bypass")
            out = await fn(stepup_url="https://t/api/stepup",
                           bearer_token="session-abc", extra_variants=False)
        # Only one result entry
        self.assertEqual(len(out["details"]["results"]), 1)


class PasskeyStepupRegistrationTest(unittest.TestCase):

    def test_tool_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        self.assertIn("probe_passkey_stepup_bypass", names)


class PickToolRoutingTest(unittest.IsolatedAsyncioTestCase):

    async def _route(self, query: str) -> str:
        from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl
        return await pick_tool_impl(query)

    async def test_passkey_stepup_routes(self):
        out = await self._route("test for passkey stepup bypass on target")
        self.assertIn("probe_passkey_stepup_bypass", out)

    async def test_cve_routes(self):
        out = await self._route("check CVE-2026-32879")
        self.assertIn("probe_passkey_stepup_bypass", out)

    async def test_mcp_atlassian_routes(self):
        out = await self._route("probe mcp-atlassian for known CVEs")
        self.assertIn("probe_mcp_server_attacks", out)


if __name__ == "__main__":
    unittest.main()
