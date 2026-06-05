"""W24-a — verdict-refactor wave: analyze_reset_tokens, test_session_lifecycle,
analyze_dom, probe_xss_executed migrated from string return to W7 VerdictResult dict."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.testing._verdict import is_actionable, to_assess_evidence


def _get_tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class AnalyzeResetTokensVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_too_few_tokens_returns_error_verdict(self):
        fn = _get_tool("analyze_reset_tokens")
        out = await fn(tokens=["abc"])
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn(">=2 tokens", out["evidence_summary"])

    async def test_capture_times_length_mismatch_error(self):
        fn = _get_tool("analyze_reset_tokens")
        out = await fn(tokens=["a", "b"], capture_times=[1.0])
        self.assertEqual(out["verdict"], "ERROR")

    async def test_random_tokens_failed(self):
        fn = _get_tool("analyze_reset_tokens")
        # High-entropy random-looking hex tokens
        tokens = [
            "9f3e7a1c8b2d4f5e6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a",
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "f5e4d3c2b1a09f8e7d6c5b4a39281706a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0",
            "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c",
        ]
        out = await fn(tokens=tokens)
        self.assertIn(out["verdict"], ("FAILED", "SUSPECTED"))
        self.assertEqual(out["vuln_type"], "weak_token_generation")
        self.assertIn("mean_entropy_bits", out["details"])

    async def test_sequential_hex_tokens_confirmed(self):
        fn = _get_tool("analyze_reset_tokens")
        # Sequential integer suffix — should fire CONFIRMED (sequential + low entropy)
        tokens = [
            "reset00000001",
            "reset00000002",
            "reset00000003",
            "reset00000004",
            "reset00000005",
        ]
        out = await fn(tokens=tokens)
        # Sequential + low-entropy = 2 signals → CONFIRMED
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertTrue(out["details"]["sequential"])

    async def test_returns_human_summary(self):
        fn = _get_tool("analyze_reset_tokens")
        out = await fn(tokens=["aaaaaaaa", "bbbbbbbb"])
        self.assertIn("human_summary", out)
        self.assertIn("analyze_reset_tokens", out["human_summary"])


class SessionLifecycleVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_auth_returns_error(self):
        fn = _get_tool("test_session_lifecycle")
        out = await fn(protected_url="https://t/p", logout_url="https://t/o")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("bearer_token or cookies", out["evidence_summary"])

    async def test_not_revoked_confirmed(self):
        # Baseline 200 / logout 200 / replay 200 same len → CONFIRMED
        responses = iter([
            {"status_code": 200, "response_length": 1234, "history_index": 10},  # baseline
            {"status_code": 200, "response_length": 12, "history_index": 11},   # logout
            {"status_code": 200, "response_length": 1234, "history_index": 12},  # replay
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.session_lifecycle.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _get_tool("test_session_lifecycle")
            out = await fn(
                protected_url="https://t/p", logout_url="https://t/o",
                bearer_token="abc",
            )
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["vuln_type"], "session_not_invalidated")
        self.assertIn(12, out["logger_indices"])  # replay
        ev = to_assess_evidence(out)
        self.assertEqual(ev["logger_index"], 10)  # first index

    async def test_revoked_failed(self):
        # Replay returns 401 → FAILED
        responses = iter([
            {"status_code": 200, "response_length": 1234, "history_index": 10},
            {"status_code": 200, "response_length": 12, "history_index": 11},
            {"status_code": 401, "response_length": 100, "history_index": 12},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.session_lifecycle.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _get_tool("test_session_lifecycle")
            out = await fn(
                protected_url="https://t/p", logout_url="https://t/o",
                bearer_token="abc",
            )
        self.assertEqual(out["verdict"], "FAILED")
        self.assertFalse(is_actionable(out))

    async def test_partial_suspected(self):
        # Same status, large body delta → SUSPECTED
        responses = iter([
            {"status_code": 200, "response_length": 5000, "history_index": 10},
            {"status_code": 200, "response_length": 12, "history_index": 11},
            {"status_code": 200, "response_length": 2000, "history_index": 12},
        ])

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.auth.session_lifecycle.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _get_tool("test_session_lifecycle")
            out = await fn(
                protected_url="https://t/p", logout_url="https://t/o",
                bearer_token="abc",
            )
        self.assertEqual(out["verdict"], "SUSPECTED")


class AnalyzeDomVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_error_passthrough(self):
        with patch("burpsuite_mcp.tools.dom.client.post",
                   new=AsyncMock(return_value={"error": "no such index"})):
            fn = _get_tool("analyze_dom")
            out = await fn(index=99999)
        self.assertEqual(out["verdict"], "ERROR")

    async def test_clean_response_failed(self):
        with patch("burpsuite_mcp.tools.dom.client.post",
                   new=AsyncMock(return_value={"html_analysis": {}, "js_analysis": {}})):
            fn = _get_tool("analyze_dom")
            out = await fn(index=1)
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["vuln_type"], "dom_security_signals")

    async def test_flows_trigger_suspected(self):
        data = {
            "html_analysis": {},
            "js_analysis": {
                "sinks": [{"type": "innerHTML", "risk": "high", "context": "a.innerHTML=x"}],
                "sources": [{"type": "location.hash", "risk": "high", "context": "loc.hash"}],
                "potential_flows": [
                    {"source": "location.hash", "sink": "innerHTML",
                     "description": "hash → innerHTML"},
                ],
                "prototype_pollution": [],
                "dangerous_patterns": [],
            },
        }
        with patch("burpsuite_mcp.tools.dom.client.post",
                   new=AsyncMock(return_value=data)):
            fn = _get_tool("analyze_dom")
            out = await fn(index=5)
        self.assertEqual(out["verdict"], "SUSPECTED")
        self.assertGreaterEqual(out["details"]["potential_flows"], 1)
        self.assertEqual(out["proxy_indices"], [5])


class ProbeXssExecutedScopeTest(unittest.IsolatedAsyncioTestCase):

    async def test_scope_reject_returns_error(self):
        with patch("burpsuite_mcp.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": False})):
            fn = _get_tool("probe_xss_executed")
            out = await fn(url="https://oos.example.com/x", param="q")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("not in scope", out["evidence_summary"])

    async def test_scope_check_error_returns_error(self):
        with patch("burpsuite_mcp.client.check_scope",
                   new=AsyncMock(return_value={"error": "no scope cfg"})):
            fn = _get_tool("probe_xss_executed")
            out = await fn(url="https://nope/", param="q")
        self.assertEqual(out["verdict"], "ERROR")


class RegistrationTest(unittest.TestCase):

    def test_all_four_tools_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        for required in (
            "analyze_reset_tokens",
            "test_session_lifecycle",
            "analyze_dom",
            "probe_xss_executed",
        ):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
