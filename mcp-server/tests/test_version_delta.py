"""adapt_poc_to_version — cross-version PoC adaptation.

The behaviour under test is the one that costs findings: a PoC written for
version A fired verbatim at version B, failing on a shape change and being
recorded as "not vulnerable".
"""

import unittest

from burpsuite_mcp import server
from burpsuite_mcp.tools.version_delta import (
    assess_applicability,
    compare_versions,
    detect_ecosystem,
    parse_version,
    version_distance,
)


class VersionParsing(unittest.TestCase):
    def test_parses_common_shapes(self):
        self.assertEqual(parse_version("v14.2.3")[0], (14, 2, 3))
        self.assertEqual(parse_version("2.10")[0], (2, 10, 0))
        self.assertEqual(parse_version("5")[0], (5, 0, 0))
        self.assertEqual(parse_version("1.2.3-rc1")[0], (1, 2, 3))

    def test_unparseable_is_none(self):
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version("unknown"))

    def test_distance_bands(self):
        self.assertEqual(version_distance("14.2.3", "14.2.9"), "patch")
        self.assertEqual(version_distance("14.2.3", "14.5.0"), "minor")
        self.assertEqual(version_distance("14.2.3", "15.0.0"), "major")
        self.assertEqual(version_distance("14.2.3", "14.2.3"), "same")

    def test_compare(self):
        self.assertEqual(compare_versions("2.0.0", "1.9.9"), 1)
        self.assertEqual(compare_versions("1.0.0", "1.0.1"), -1)
        self.assertEqual(compare_versions("1.0.0", "1.0.0"), 0)


class Applicability(unittest.TestCase):
    def test_patched_target_is_flagged_before_firing(self):
        verdict, why = assess_applicability("14.2.3", "14.2.9", "14.2.5")
        self.assertEqual(verdict, "LIKELY_PATCHED")
        self.assertIn("14.2.5", why)

    def test_minor_gap_demands_adaptation(self):
        verdict, _ = assess_applicability("14.2.3", "14.5.0", "")
        self.assertEqual(verdict, "ADAPT_REQUIRED")

    def test_major_gap_demands_adaptation(self):
        verdict, _ = assess_applicability("14.2.3", "15.1.0", "")
        self.assertEqual(verdict, "ADAPT_REQUIRED")

    def test_patch_gap_applies_as_is(self):
        verdict, _ = assess_applicability("14.2.3", "14.2.4", "")
        self.assertEqual(verdict, "APPLIES_AS_IS")

    def test_missing_target_version_is_unknown_not_a_guess(self):
        verdict, why = assess_applicability("14.2.3", "", "")
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("Fingerprint", why)


class EcosystemDetection(unittest.TestCase):
    def test_detects_from_component_or_stack(self):
        self.assertEqual(detect_ecosystem("next.js"), "nextjs")
        self.assertEqual(detect_ecosystem("Next.js 14"), "nextjs")
        self.assertEqual(detect_ecosystem("apollo-server"), "apollo")
        self.assertEqual(detect_ecosystem("unknown-thing", "node,express"), "express")
        self.assertEqual(detect_ecosystem("mystery-cms"), "")


class ToolOutput(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = staticmethod(
            server.mcp._tool_manager._tools["adapt_poc_to_version"].fn
        )

    async def test_patched_target_short_circuits_without_variants(self):
        out = await self.tool(
            component="next.js", poc_version="14.2.3",
            target_version="14.2.9", fixed_version="14.2.5",
            cve_id="CVE-2026-44575", target_url="https://x.test/",
        )
        self.assertIn("LIKELY_PATCHED", out)
        self.assertIn("DO THIS INSTEAD", out)
        # Must not hand over a fire-ready probe call for an already-fixed target.
        self.assertNotIn("probe_cve_with_variants", out)

    async def test_minor_gap_emits_axes_and_next_calls(self):
        out = await self.tool(
            component="next.js", poc_version="14.2.3", target_version="14.6.0",
            cve_id="CVE-2026-44575", target_url="https://x.test/",
            poc_payload="0:[\"$\",\"$L1\"]",
        )
        self.assertIn("ADAPT_REQUIRED", out)
        self.assertIn("WHAT BREAKS A CROSS-VERSION PoC HERE", out)
        self.assertIn("Server Action", out)          # ecosystem-specific axis
        self.assertIn("probe_cve_with_variants", out)
        # The interpretation table is the point — it stops a 400 being read
        # as "not vulnerable".
        self.assertIn("envelope wrong", out)

    async def test_advisory_lookups_come_last(self):
        out = await self.tool(
            component="struts2", poc_version="2.5.30", target_version="2.5.33",
        )
        axes_at = out.index("WHAT BREAKS A CROSS-VERSION PoC HERE")
        refs_at = out.index("CONFIRM THE REASONING")
        self.assertLess(axes_at, refs_at,
                        "advisory lookups must not lead the output")

    async def test_requires_component(self):
        out = await self.tool(component="")
        self.assertIn("Error", out)


if __name__ == "__main__":
    unittest.main()
