"""Scope-mode persistence — operator vs strict, on-disk roundtrip."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from burpsuite_mcp.tools import _scope_mode


class ScopeModePersistenceTest(unittest.TestCase):
    def test_default_is_operator(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                self.assertEqual(_scope_mode.get_mode(), "operator")

    def test_set_then_get_strict(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                _scope_mode.set_mode("strict")
                self.assertEqual(_scope_mode.get_mode(), "strict")
                state_file = Path(tmp) / "_scope_mode.json"
                self.assertTrue(state_file.exists())
                self.assertEqual(
                    json.loads(state_file.read_text())["mode"], "strict"
                )

    def test_invalid_mode_rejected(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                with self.assertRaises(ValueError):
                    _scope_mode.set_mode("loose")


from unittest.mock import AsyncMock, patch

from burpsuite_mcp.tools import scope as scope_mod
from mcp.server.fastmcp import FastMCP


class ConfigureScopeModeParamTest(unittest.TestCase):
    def _get_tool(self):
        mcp = FastMCP("test")
        scope_mod.register(mcp)
        return mcp._tool_manager.get_tool("configure_scope").fn

    def test_mode_strict_persists_and_forwards(self):
        import asyncio
        configure_scope = self._get_tool()
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                with patch("burpsuite_mcp.tools.scope.client.post",
                           new=AsyncMock(return_value={"included": 1})) as p:
                    asyncio.run(configure_scope(
                        include=["https://x.com"], mode="strict"
                    ))
                    self.assertEqual(_scope_mode.get_mode(), "strict")
                    sent = p.call_args.kwargs["json"]
                    self.assertEqual(sent["mode"], "strict")

    def test_mode_operator_is_default(self):
        import asyncio
        configure_scope = self._get_tool()
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                with patch("burpsuite_mcp.tools.scope.client.post",
                           new=AsyncMock(return_value={"included": 1})) as p:
                    asyncio.run(configure_scope(include=["https://x.com"]))
                    self.assertEqual(_scope_mode.get_mode(), "operator")
                    self.assertEqual(p.call_args.kwargs["json"]["mode"], "operator")


from burpsuite_mcp.tools.advisor.assess import assess_finding_impl


class AssessFindingQ1OperatorModeTest(unittest.TestCase):
    """Q1 (scope) defers to scope mode: operator trusts operator (A5)."""

    def test_q1_passes_in_operator_mode_for_unconfigured_host(self):
        import asyncio
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                _scope_mode.set_mode("operator")
                # Mock the extension scope check to FAIL (out-of-scope) — would
                # normally cause Q1 to verdict DO NOT REPORT. Operator mode
                # should defer before the call ever happens.
                with patch(
                    "burpsuite_mcp.tools.advisor.assess.client.post",
                    new=AsyncMock(return_value={"in_scope": False}),
                ) as post_mock, patch(
                    "burpsuite_mcp.tools.advisor.assess.client.get",
                    new=AsyncMock(return_value={"error": "unused"}),
                ):
                    result = asyncio.run(assess_finding_impl(
                        vuln_type="xss",
                        evidence="payload reflected in <script> context, alert(1) executed",
                        endpoint="https://unconfigured-host.example.com/q",
                        parameter="q",
                        domain="unconfigured-host.example.com",
                    ))
                    self.assertIsInstance(result, str)
                    self.assertIn("operator-mode", result)
                    self.assertNotIn("Q1 FAIL", result)
                    # Scope endpoint was deferred — never called.
                    post_mock.assert_not_awaited()

    def test_q1_strict_mode_still_blocks_out_of_scope(self):
        import asyncio
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                _scope_mode.set_mode("strict")
                with patch(
                    "burpsuite_mcp.tools.advisor.assess.client.post",
                    new=AsyncMock(return_value={"in_scope": False}),
                ), patch(
                    "burpsuite_mcp.tools.advisor.assess.client.get",
                    new=AsyncMock(return_value={"error": "unused"}),
                ):
                    result = asyncio.run(assess_finding_impl(
                        vuln_type="xss",
                        evidence="payload reflected in <script> context",
                        endpoint="https://unconfigured-host.example.com/q",
                        parameter="q",
                        domain="unconfigured-host.example.com",
                    ))
                    self.assertIn("Q1 FAIL", result)
                    self.assertIn("DO NOT REPORT", result)


if __name__ == "__main__":
    unittest.main()
