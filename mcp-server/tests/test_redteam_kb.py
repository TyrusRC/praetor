"""Red-team knowledge tools: GTFOBins / LOLBAS lookup + tool guide.

These are reference data the agent reasons over after host/network access —
verify the lookups resolve real binaries, filter by function, tolerate paths
and .exe suffixes, and fail helpfully on a miss.
"""

import unittest

from praetor import server
from praetor.tools.redteam._gtfobins import GTFOBINS
from praetor.tools.redteam._lolbas import LOLBAS
from praetor.tools.redteam._tooling import REDTEAM_TOOLS


def _tool(name):
    return server.mcp._tool_manager._tools[name].fn


class TestRegistration(unittest.TestCase):
    def test_tools_are_registered(self):
        for name in ("lookup_gtfobins", "lookup_lolbas", "redteam_tool_guide"):
            self.assertIn(name, server.mcp._tool_manager._tools)


class TestGtfobins(unittest.IsolatedAsyncioTestCase):
    async def test_find_suid_breakout(self):
        out = await _tool("lookup_gtfobins")("find", "suid")
        self.assertIn("-exec /bin/sh", out)
        self.assertIn("[suid]", out)

    async def test_full_path_resolves(self):
        out = await _tool("lookup_gtfobins")("/usr/bin/vim")
        self.assertIn("GTFOBins: vim", out)

    async def test_function_filter_narrows_output(self):
        out = await _tool("lookup_gtfobins")("python3", "sudo")
        self.assertIn("[sudo]", out)
        self.assertNotIn("[suid]", out)

    async def test_unknown_binary_is_helpful(self):
        out = await _tool("lookup_gtfobins")("definitely_not_a_binary")
        self.assertIn("No GTFOBins entry", out)

    async def test_unknown_function_lists_available(self):
        out = await _tool("lookup_gtfobins")("bash", "nonexistent-fn")
        self.assertIn("Available:", out)


class TestLolbas(unittest.IsolatedAsyncioTestCase):
    async def test_certutil_download(self):
        out = await _tool("lookup_lolbas")("certutil", "download")
        self.assertIn("urlcache", out)

    async def test_exe_suffix_optional(self):
        a = await _tool("lookup_lolbas")("rundll32")
        b = await _tool("lookup_lolbas")("rundll32.exe")
        self.assertIn("LOLBAS: rundll32.exe", a)
        self.assertEqual(a, b)


class TestToolGuide(unittest.IsolatedAsyncioTestCase):
    async def test_tier_c_marked_burp_blind(self):
        out = await _tool("redteam_tool_guide")("impacket")
        self.assertIn("tier C", out)
        self.assertIn("routes_through_burp=False", out)
        self.assertIn("apt install", out)

    async def test_hydra_flags_rule6_conflict(self):
        out = await _tool("redteam_tool_guide")("hydra")
        self.assertIn("Rule 6", out)

    async def test_tier_filter(self):
        out = await _tool("redteam_tool_guide")("", "A")
        self.assertIn("gobuster", out)
        self.assertNotIn("impacket", out)


class TestDataIntegrity(unittest.TestCase):
    def test_datasets_non_trivial(self):
        self.assertGreaterEqual(len(GTFOBINS), 25)
        self.assertGreaterEqual(len(LOLBAS), 20)
        self.assertGreaterEqual(len(REDTEAM_TOOLS), 12)

    def test_every_gtfobins_function_has_commands(self):
        for binary, funcs in GTFOBINS.items():
            for fname, cmds in funcs.items():
                self.assertIsInstance(cmds, list, f"{binary}.{fname}")
                self.assertTrue(all(isinstance(c, str) and c for c in cmds), f"{binary}.{fname}")

    def test_tooling_entries_have_required_keys(self):
        for name, meta in REDTEAM_TOOLS.items():
            for k in ("tier", "routes_burp", "purpose", "install"):
                self.assertIn(k, meta, f"{name} missing {k}")
            self.assertIn(meta["tier"], ("A", "B", "C"), name)


if __name__ == "__main__":
    unittest.main()
