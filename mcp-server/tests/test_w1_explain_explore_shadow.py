"""Wave 1 — explain_finding / explore_issue / shadow_repeater / KB augments."""

import json
import unittest
from pathlib import Path

import burpsuite_mcp.tools.shadow_repeater as shadow_repeater_mod
from burpsuite_mcp.tools.notes import explain_finding as explain_mod
from burpsuite_mcp.tools.notes import explore_issue as explore_mod


KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


class W1KbAugmentTest(unittest.TestCase):

    def test_browser_powered_csd_contexts_present(self):
        d = json.loads((KB / "http_desync.json").read_text())
        self.assertIn("browser_powered_csd_intranet", d["contexts"])
        self.assertIn("browser_powered_csd_internal", d["contexts"])
        for k in ("browser_powered_csd_intranet", "browser_powered_csd_internal"):
            ctx = d["contexts"][k]
            self.assertTrue(ctx.get("probes"))
            for p in ctx["probes"]:
                self.assertTrue(p.get("matchers"))

    def test_cache_deception_v2_parser_variants_present(self):
        d = json.loads((KB / "cache_deception_v2.json").read_text())
        for k in ("fragment_split_parser_discrepancy",
                  "double_extension_parser_split",
                  "normalised_path_traversal_split"):
            self.assertIn(k, d["contexts"])


class W1ExploreIssueTest(unittest.TestCase):

    def test_probes_table_has_common_classes(self):
        for cls in ("xss", "sqli", "ssrf", "idor", "jwt", "oauth",
                    "open_redirect", "csrf", "graphql", "websocket"):
            self.assertIn(cls, explore_mod._PROBES)
            self.assertTrue(explore_mod._PROBES[cls])

    def test_probes_have_tool_and_rationale(self):
        for cls, probes in explore_mod._PROBES.items():
            for p in probes:
                self.assertIn("tool", p, f"{cls} missing tool")
                self.assertIn("rationale", p, f"{cls} missing rationale")


class W1ExplainNeverSubmitTest(unittest.TestCase):

    def test_never_submit_hints_include_canonical(self):
        for cls in ("self_xss", "open_redirect", "info_disclosure",
                    "username_enumeration", "version_disclosure"):
            self.assertIn(cls, explain_mod._NEVER_SUBMIT_HINTS)

    def test_chain_targets_keyed_by_vuln_class(self):
        for cls in ("open_redirect", "info_disclosure", "csrf", "xss",
                    "ssrf", "host_header", "subdomain_takeover"):
            self.assertIn(cls, explain_mod._CHAIN_TARGETS)


class W1ShadowRepeaterMutationsTest(unittest.TestCase):

    def test_url_encode_yields_percent_form(self):
        out = shadow_repeater_mod._mutate("abc", ["url_encode"])
        self.assertEqual(out, ["%61%62%63"])

    def test_case_toggle_yields_swapped(self):
        out = shadow_repeater_mod._mutate("aB", ["case_toggle"])
        self.assertEqual(out, ["Ab"])

    def test_null_byte_appends(self):
        out = shadow_repeater_mod._mutate("file", ["null_byte"])
        self.assertEqual(out, ["file\x00.txt"])

    def test_default_classes_produce_diverse_variants(self):
        out = shadow_repeater_mod._mutate("a b'", shadow_repeater_mod._DEFAULT_CLASSES)
        self.assertGreaterEqual(len(out), 4)
        self.assertEqual(len(out), len(set(out)))

    def test_seed_excluded_from_output(self):
        out = shadow_repeater_mod._mutate("PRAETOR", ["case_toggle"])
        self.assertNotIn("PRAETOR", out)


if __name__ == "__main__":
    unittest.main()
