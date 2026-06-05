"""W22-d — tool tiering: pick_tool routing extensions + list_tier1_tools."""

from __future__ import annotations

import unittest

from burpsuite_mcp.tools.advisor.pick_tool import (
    TIER1_HUNT_LOOP,
    pick_tool_impl,
)


class Tier1ListShapeTest(unittest.TestCase):

    def test_tier1_count_within_budget(self):
        """Tier-1 must stay between 18-30 tools — not too small to be useless,
        not too large to defeat the purpose."""
        self.assertGreaterEqual(len(TIER1_HUNT_LOOP), 18)
        self.assertLessEqual(len(TIER1_HUNT_LOOP), 30)

    def test_tier1_entries_well_formed(self):
        for entry in TIER1_HUNT_LOOP:
            self.assertEqual(len(entry), 2)
            name, purpose = entry
            self.assertIsInstance(name, str)
            self.assertIsInstance(purpose, str)
            self.assertGreater(len(name), 2)
            self.assertGreater(len(purpose), 4)

    def test_tier1_no_duplicates(self):
        names = [n for n, _ in TIER1_HUNT_LOOP]
        self.assertEqual(len(names), len(set(names)),
                         f"duplicate tier-1 entries: {names}")

    def test_tier1_must_include_save_pipeline(self):
        """The save-finding pipeline is HARD (Rule 10) — its tools MUST be Tier-1."""
        names = {n for n, _ in TIER1_HUNT_LOOP}
        for required in ("assess_finding", "save_finding", "check_scope"):
            self.assertIn(required, names, f"Tier-1 missing required: {required}")

    def test_tier1_must_include_intel_load(self):
        """Rule 20a session-start gate uses load_target_intel — Tier-1."""
        names = {n for n, _ in TIER1_HUNT_LOOP}
        self.assertIn("load_target_intel", names)


class PickToolRoutingW22Test(unittest.IsolatedAsyncioTestCase):

    async def test_routes_cua_query(self):
        out = await pick_tool_impl("test for cua injection on profile page")
        self.assertIn("probe_cua_injection_surface", out)

    async def test_routes_langgrinch_query(self):
        out = await pick_tool_impl("scan for langchain langgrinch deserialization")
        self.assertIn("auto_probe", out)
        self.assertIn("ai_prompt_injection", out)

    async def test_routes_opennext_query(self):
        out = await pick_tool_impl("opennext cloudflare cdn-cgi backslash ssrf")
        self.assertIn("auto_probe", out)
        self.assertIn("edge_worker_ssrf", out)

    async def test_routes_xbow_query(self):
        out = await pick_tool_impl("run xbow benchmark XBEN-001")
        self.assertIn("run_xbow_bench", out)

    async def test_routes_msf_query(self):
        out = await pick_tool_impl("metasploit module for log4shell")
        self.assertIn("msf_search", out)

    async def test_routes_cve_query(self):
        out = await pick_tool_impl("exploit CVE-2024-XXXXX")
        self.assertIn("msf_search", out)

    async def test_routes_msf_exploit_query(self):
        out = await pick_tool_impl("fire metasploit module against target")
        self.assertIn("msf_exploit", out)

    async def test_routes_pyexploit_query(self):
        out = await pick_tool_impl("custom poc python exploit sandbox")
        self.assertIn("run_pyexploit", out)

    async def test_fallback_lists_tier1(self):
        """When no keyword matches, fallback must surface Tier-1 entry points."""
        out = await pick_tool_impl("something completely unrelated zzzz")
        self.assertIn("Tier-1", out)
        self.assertIn("load_target_intel", out)
        self.assertIn("discover_attack_surface", out)


class ListTier1ToolsRegisteredTest(unittest.TestCase):

    def test_list_tier1_tools_registered(self):
        from burpsuite_mcp import server
        self.assertIn("list_tier1_tools", server.mcp._tool_manager._tools)


class ListTier1ToolsReturnTest(unittest.IsolatedAsyncioTestCase):

    async def test_returns_full_listing(self):
        from burpsuite_mcp import server
        fn = server.mcp._tool_manager._tools["list_tier1_tools"].fn
        out = await fn()
        self.assertEqual(out["tier"], 1)
        self.assertEqual(out["count"], len(TIER1_HUNT_LOOP))
        names = {t["name"] for t in out["tools"]}
        self.assertIn("auto_probe", names)
        self.assertIn("save_finding", names)
        self.assertIn("default_chain", out)


if __name__ == "__main__":
    unittest.main()
