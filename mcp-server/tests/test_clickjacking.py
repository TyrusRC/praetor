"""Calibration for edge/test_clickjacking frameability logic + PoC generator.

The verdict must match how a browser actually decides framing: CSP
frame-ancestors is authoritative over X-Frame-Options, and the legacy XFO
ALLOW-FROM form is ignored (so it is NOT a protection). These are the cases
that flip a real clickjacking assessment between exploitable and safe.

Run: uv run python -m unittest tests.test_clickjacking -v
"""

import unittest

from praetor.tools.edge.test_clickjacking import (
    assess_frameability,
    build_clickjacking_poc,
    frame_ancestors,
)


class FrameAncestorsParseTests(unittest.TestCase):
    def test_absent_directive_returns_none(self):
        self.assertIsNone(frame_ancestors("default-src 'self'; script-src 'self'"))
        self.assertIsNone(frame_ancestors(None))

    def test_extracts_and_lowercases_sources(self):
        self.assertEqual(
            frame_ancestors("default-src 'self'; frame-ancestors 'SELF' https://T.com"),
            ["'self'", "https://t.com"],
        )

    def test_present_but_empty_is_empty_list(self):
        self.assertEqual(frame_ancestors("frame-ancestors"), [])


class FrameabilityVerdictTests(unittest.TestCase):
    def test_no_headers_is_frameable(self):
        a = assess_frameability(None, None)
        self.assertTrue(a["frameable"])

    def test_xfo_deny_protects(self):
        self.assertFalse(assess_frameability("DENY", None)["frameable"])

    def test_xfo_sameorigin_protects_cross_origin(self):
        self.assertFalse(assess_frameability("SAMEORIGIN", None)["frameable"])

    def test_xfo_allow_from_is_ignored_so_frameable(self):
        # Modern browsers ignore ALLOW-FROM — must NOT count as protection.
        a = assess_frameability("ALLOW-FROM https://good.com", None)
        self.assertTrue(a["frameable"])
        self.assertIsNone(a["protection"])

    def test_xfo_garbage_is_no_protection(self):
        self.assertTrue(assess_frameability("bogus", None)["frameable"])

    def test_csp_frame_ancestors_none_protects(self):
        self.assertFalse(assess_frameability(None, "frame-ancestors 'none'")["frameable"])

    def test_csp_frame_ancestors_self_protects_cross_origin(self):
        self.assertFalse(assess_frameability(None, "frame-ancestors 'self'")["frameable"])

    def test_csp_frame_ancestors_wildcard_is_frameable(self):
        self.assertTrue(assess_frameability(None, "frame-ancestors *")["frameable"])

    def test_csp_frame_ancestors_overrides_permissive_xfo_absence(self):
        # CSP 'none' wins even though XFO is absent.
        self.assertFalse(assess_frameability(None, "default-src 'self'; frame-ancestors 'none'")["frameable"])

    def test_csp_frame_ancestors_authoritative_over_xfo(self):
        # A browser honours frame-ancestors over XFO: CSP 'none' + XFO absent -> protected.
        # And CSP allow-list beats a (would-be) permissive XFO reading.
        self.assertFalse(assess_frameability(None, "frame-ancestors https://trusted.com")["frameable"])


class PocGeneratorTests(unittest.TestCase):
    def test_multistep_poc_has_two_decoys_and_iframe(self):
        poc = build_clickjacking_poc("https://lab/my-account", multistep=True)
        self.assertIn("firstClick", poc)
        self.assertIn("secondClick", poc)
        self.assertIn('src="https://lab/my-account"', poc)

    def test_single_poc_has_one_decoy(self):
        poc = build_clickjacking_poc("https://lab/x", multistep=False)
        self.assertNotIn("secondClick", poc)
        self.assertIn('src="https://lab/x"', poc)

    def test_poc_uses_alignable_opacity(self):
        # Must ship at a visible opacity for alignment, not the delivery 0.0001.
        self.assertIn("opacity:0.1", build_clickjacking_poc("https://lab/", True))


if __name__ == "__main__":
    unittest.main()
