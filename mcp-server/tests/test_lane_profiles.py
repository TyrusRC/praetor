"""Tool-lane profile gating (Phase 1): the substrate that lets an eager-loading
host advertise fewer tools. Covers lane classification, profile resolution, the
fail-safe (unknown -> core, core never dropped), and that the map has no phantoms.
"""

import asyncio
import unittest

from mcp.server.fastmcp import FastMCP

from praetor import _lanes


class LaneClassificationTest(unittest.TestCase):
    def test_overrides_win_over_package(self):
        # exploit pkg spans lanes — overrides must split it correctly.
        self.assertEqual(_lanes.tool_lane("confirm_sqli", "praetor.tools.exploit.x"), "web")
        self.assertEqual(_lanes.tool_lane("msf_exploit", "praetor.tools.exploit.x"), "msf")
        self.assertEqual(_lanes.tool_lane("probe_mcp_server_attacks", "praetor.tools.exploit.x"), "llm")
        # redteam pkg is network, but the Ghostwriter hub is core.
        self.assertEqual(_lanes.tool_lane("record_loot", "praetor.tools.redteam.x"), "network")
        self.assertEqual(_lanes.tool_lane("sync_to_ghostwriter", "praetor.tools.redteam.x"), "core")

    def test_package_default(self):
        self.assertEqual(_lanes.tool_lane("run_nmap", "praetor.tools.network._x"), "network")
        self.assertEqual(_lanes.tool_lane("mobile_devices", "praetor.tools.mobile._x"), "mobile")
        self.assertEqual(_lanes.tool_lane("run_tlsx", "praetor.tools.recon_pd._x"), "recon_ext")

    def test_unknown_defaults_to_core_failsafe(self):
        self.assertEqual(_lanes.tool_lane("brand_new_tool", "praetor.tools.brandnew._x"), "core")


class ProfileResolutionTest(unittest.TestCase):
    def test_named_profiles(self):
        self.assertEqual(_lanes.resolve_lanes("core"), set())
        self.assertEqual(_lanes.resolve_lanes("web"), {"web"})
        self.assertEqual(_lanes.resolve_lanes("all"), set(_lanes.ALL_LANES))
        self.assertEqual(_lanes.resolve_lanes("network"), {"network"})

    def test_comma_list(self):
        self.assertEqual(_lanes.resolve_lanes("web,network,mobile"), {"web", "network", "mobile"})

    def test_bad_tokens_ignored_then_fallback(self):
        self.assertEqual(_lanes.resolve_lanes("web,bogus"), {"web"})
        # all-invalid -> default profile (all)
        self.assertEqual(_lanes.resolve_lanes("bogus,nope"), set(_lanes.ALL_LANES))
        self.assertEqual(_lanes.resolve_lanes(""), set(_lanes.ALL_LANES))


class ApplyProfileTest(unittest.TestCase):
    def _mk(self):
        m = FastMCP("t")

        @m.tool()
        async def core_x() -> int:
            return 1

        @m.tool()
        async def web_x() -> int:
            return 1

        _lanes._TOOL_LANE["web_x"] = "web"
        self.addCleanup(lambda: _lanes._TOOL_LANE.pop("web_x", None))
        return m

    def test_core_kept_optional_dropped(self):
        m = self._mk()
        _lanes.apply_profile(m, "core")  # no optional lanes
        names = set(m._tool_manager._tools)
        self.assertIn("core_x", names)
        self.assertNotIn("web_x", names)

    def test_enabled_lane_kept(self):
        m = self._mk()
        _lanes.apply_profile(m, "web")
        names = set(m._tool_manager._tools)
        self.assertIn("core_x", names)
        self.assertIn("web_x", names)

    def test_summary_recorded(self):
        m = self._mk()
        s = _lanes.apply_profile(m, "core")
        self.assertEqual(s["profile"], "core")
        self.assertEqual(s["removed"], 1)
        self.assertIs(_lanes.LAST_APPLIED, s)


class RealRegistryGuardTest(unittest.TestCase):
    """Against the live server: no phantom overrides, and default `all` keeps all."""

    def test_no_phantom_overrides_and_default_keeps_all(self):
        from praetor.server import mcp  # imported with default profile `all`
        names = {t.name for t in asyncio.run(mcp.list_tools())}
        phantom = [n for n in _lanes._TOOL_LANE if n not in names]
        self.assertEqual(phantom, [], f"overrides for non-existent tools: {phantom}")
        # default is `all` -> every optional lane present, plus core control tool.
        # (Assert against the live registry, not the mutable LAST_APPLIED global,
        # which other tests in this file legitimately overwrite.)
        self.assertIn("get_profile", names)
        self.assertIn("save_finding", names)  # core
        self.assertIn("run_nmap", names)      # network lane
        self.assertIn("mobile_devices", names)  # mobile lane


if __name__ == "__main__":
    unittest.main()
