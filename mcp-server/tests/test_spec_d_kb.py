"""Spec D KB content — presence + parse of new contexts/files/variants."""
import json
import unittest
from pathlib import Path

KB = Path(__file__).parent.parent / "src" / "praetor" / "knowledge"


def _load(name):
    return json.loads((KB / name).read_text())


class SstiErrorOracleTest(unittest.TestCase):
    ENGINES = ["ssti_python.json", "ssti_php.json", "ssti_java.json",
               "ssti_js.json", "ssti_elixir.json"]

    def test_engines_have_error_oracle_contexts(self):
        for f in self.ENGINES:
            ctxs = _load(f)["contexts"]
            self.assertIn("error_based_blind", ctxs, f"{f} missing error_based_blind")
            self.assertIn("boolean_error_blind", ctxs, f"{f} missing boolean_error_blind")

    def test_error_context_has_matcher(self):
        for f in self.ENGINES:
            probe = _load(f)["contexts"]["error_based_blind"]["probes"][0]
            self.assertTrue(probe["matchers"], f"{f} error probe has no matcher")
            self.assertIn("payload", probe)

    def test_elixir_parent_valid(self):
        data = _load("ssti_elixir.json")
        self.assertEqual(data["category"], "ssti_elixir")
        self.assertGreater(len(data["contexts"]), 0)


class SsrfRedirectLoopTest(unittest.TestCase):
    def test_context_present(self):
        ctxs = _load("ssrf_bypass.json")["contexts"]
        self.assertIn("redirect_loop_full_response_leak", ctxs)
        probe = ctxs["redirect_loop_full_response_leak"]["probes"][0]
        self.assertTrue(probe["matchers"])


class NextjsMiddlewareVariantTest(unittest.TestCase):
    def test_cve_maps_to_class(self):
        from praetor.tools.cve_variant_probe import _resolve_class
        self.assertEqual(_resolve_class("CVE-2026-44575", ""),
                         "nextjs_middleware_bypass")
        self.assertEqual(_resolve_class("CVE-2026-44574", ""),
                         "nextjs_middleware_bypass")

    def test_generator_emits_variants(self):
        from praetor.tools.cve_variant_probe import _GENERATORS
        gen = _GENERATORS["nextjs_middleware_bypass"]
        variants = gen("/admin", "CANARY123", "")
        labels = {v["label"] for v in variants}
        self.assertIn("mw_bypass.rsc_suffix", labels)
        self.assertIn("mw_bypass.query_route_override", labels)
        self.assertTrue(all("CANARY123" in json.dumps(v) for v in variants))

    def test_rsc_dos_context_present(self):
        ctxs = _load("react_server_components.json")["contexts"]
        self.assertIn("server_function_deser_dos", ctxs)


if __name__ == "__main__":
    unittest.main()
