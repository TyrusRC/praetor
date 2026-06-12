"""W31-c — 2026 H2 fresh CVE intake (conservative).

Covers:
- New KB parents (sveltekit.json + nuxt.json) load + schema-valid
- 21 new CVE contexts merged into 8 existing parent KBs
- CVE-2026-44578 routed to nextjs_ws_upgrade_ssrf class with variant pack
- _WS_SSRF_MARKERS detect IMDS/GCP/Azure metadata canaries
- probe_sveltekit_devalue_dos / probe_nuxt_island_authz importable
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

KB_DIR = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


NEW_KB_PARENTS = ("sveltekit.json", "nuxt.json")


_EXPECTED_NEW_CONTEXTS = {
    "prototype_pollution.json": {
        "axios_merge_read_side_pp_2026",
        "flatted_parse_array_prototype_2026",
        "convict_startswith_bypass_of_fix_2026",
        "deepobj_merge_rce_2026",
    },
    "jwt.json": {
        "jwe_wrapped_plain_inner_bypass_2026",
        "pyjwt_algorithm_confusion_2026",
        "unknown_alg_signature_skip_2026",
    },
    "oauth.json": {
        "oidc_iss_validation_bypass_2026",
        "user_agent_auth_bypass_2026",
        "state_omission_account_linking_2026",
    },
    "ssrf.json": {
        "lmdeploy_vision_url_ssrf_2026",
        "kyverno_admission_webhook_ssrf_2026",
        "phpspreadsheet_xlsx_hyperlink_ssrf_2026",
    },
    "ai_prompt_injection.json": {
        "semantic_kernel_tool_call_rce_2026",
        "windsurf_html_mcp_register_2026",
    },
    "mcp_server_attacks.json": {
        "apollo_mcp_streamablehttp_dns_rebind_2026",
        "ms_mcp_tool_description_hijack_2026",
    },
    "nextjs_cache_poisoning.json": {
        "i18n_middleware_strip_bypass_2026",
        "ws_upgrade_ssrf_2026",
        "next_image_unbounded_cache_dos_2026",
    },
    "sqli.json": {
        "litellm_pre_auth_header_injection_2026",
    },
}


class NewKbParentsTest(unittest.TestCase):
    def test_sveltekit_parent_loads(self):
        kb = json.loads((KB_DIR / "sveltekit.json").read_text())
        self.assertEqual(kb["category"], "sveltekit")
        self.assertIn("contexts", kb)
        self.assertIn("devalue_cyclic_dos", kb["contexts"])
        self.assertIn("form_action_authz_drift", kb["contexts"])
        self.assertIn("load_function_data_leak", kb["contexts"])
        # chain_with required per W31-a meta uplift
        self.assertIn("chain_with", kb)

    def test_nuxt_parent_loads(self):
        kb = json.loads((KB_DIR / "nuxt.json").read_text())
        self.assertEqual(kb["category"], "nuxt")
        self.assertIn("contexts", kb)
        self.assertIn("island_endpoint_authz", kb["contexts"])
        self.assertIn("og_image_renderer_dos", kb["contexts"])
        self.assertIn("server_routes_middleware_bypass", kb["contexts"])
        self.assertIn("chain_with", kb)

    def test_loader_picks_up_new_parents(self):
        from burpsuite_mcp.tools.scan._helpers import _load_knowledge
        self.assertIsNotNone(_load_knowledge("sveltekit"))
        self.assertIsNotNone(_load_knowledge("nuxt"))

    def test_all_probes_have_payload_and_matchers(self):
        for parent in NEW_KB_PARENTS:
            kb = json.loads((KB_DIR / parent).read_text())
            for ctx_name, ctx in kb["contexts"].items():
                self.assertIn("probes", ctx, f"{parent}:{ctx_name}")
                for probe in ctx["probes"]:
                    self.assertIn("payload", probe, f"{parent}:{ctx_name}")
                    self.assertIn("matchers", probe, f"{parent}:{ctx_name}")


class CveContextMergesTest(unittest.TestCase):
    def test_all_21_contexts_landed(self):
        for parent, expected in _EXPECTED_NEW_CONTEXTS.items():
            kb = json.loads((KB_DIR / parent).read_text())
            actual = set(kb.get("contexts", {}).keys())
            missing = expected - actual
            self.assertFalse(
                missing,
                f"{parent} missing contexts: {missing}",
            )

    def test_skipped_suspicious_cve(self):
        """CVE-2026-12345 (Apollo Federation) was flagged as AI-hallucinated.
        Make sure no graphql/apollo context references it."""
        for parent in ("ai_prompt_injection.json", "mcp_server_attacks.json"):
            kb = json.loads((KB_DIR / parent).read_text())
            txt = json.dumps(kb)
            self.assertNotIn("CVE-2026-12345", txt)


class CveVariantPackTest(unittest.TestCase):
    def test_cve_2026_44578_routes_to_ws_ssrf(self):
        from burpsuite_mcp.tools.cve_variant_probe import _resolve_class
        self.assertEqual(_resolve_class("CVE-2026-44578", ""), "nextjs_ws_upgrade_ssrf")

    def test_ws_ssrf_variants_generated(self):
        from burpsuite_mcp.tools.cve_variant_probe import _nextjs_ws_ssrf_variants
        variants = _nextjs_ws_ssrf_variants("", "PRAETOR-AB12CD34", "")
        labels = [v["label"] for v in variants]
        self.assertIn("ws_ssrf.aws_imds", labels)
        self.assertIn("ws_ssrf.gcp_metadata", labels)
        self.assertIn("ws_ssrf.azure_imds", labels)
        self.assertIn("ws_ssrf.loopback", labels)
        for v in variants:
            self.assertEqual(v["method"], "GET")
            self.assertEqual(v["headers"].get("Upgrade"), "websocket")
            self.assertEqual(v["headers"].get("Connection"), "upgrade")
            self.assertEqual(v["headers"].get("X-Praetor-Canary"), "PRAETOR-AB12CD34")

    def test_ws_ssrf_markers_match_aws(self):
        from burpsuite_mcp.tools.cve_variant_probe import _score_response
        body = (
            '{"Code":"Success","LastUpdated":"...",'
            '"Type":"AWS-HMAC","AccessKeyId":"ASIA...","SecretAccessKey":"..."}'
        )
        verdict, _, _ = _score_response("nextjs_ws_upgrade_ssrf", "", 200, "", body)
        # Marker hit + status 200 → SUSPECTED at minimum (no canary echo path)
        self.assertEqual(verdict, "SUSPECTED")

    def test_ws_ssrf_markers_match_gcp(self):
        from burpsuite_mcp.tools.cve_variant_probe import _score_response
        verdict, _, _ = _score_response(
            "nextjs_ws_upgrade_ssrf", "",
            200,
            "X-Google-Metadata-Request: True",
            "",
        )
        self.assertEqual(verdict, "SUSPECTED")

    def test_ws_ssrf_canary_echo_confirmed(self):
        from burpsuite_mcp.tools.cve_variant_probe import _score_response
        verdict, conf, _ = _score_response(
            "nextjs_ws_upgrade_ssrf",
            "PRAETOR-FFFFAAAA",
            200,
            "X-Echo: PRAETOR-FFFFAAAA",
            "",
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertGreaterEqual(conf, 0.85)


class NewToolsImportableTest(unittest.TestCase):
    def test_sveltekit_probe_imports(self):
        from burpsuite_mcp.tools import sveltekit_probe
        self.assertTrue(hasattr(sveltekit_probe, "register"))

    def test_nuxt_island_probe_imports(self):
        from burpsuite_mcp.tools import nuxt_island_probe
        self.assertTrue(hasattr(nuxt_island_probe, "register"))

    def test_sveltekit_devalue_cycles_well_formed(self):
        from burpsuite_mcp.tools.sveltekit_probe import _DEVALUE_CYCLES
        self.assertGreaterEqual(len(_DEVALUE_CYCLES), 3)
        # All should be valid JSON arrays
        for p in _DEVALUE_CYCLES:
            parsed = json.loads(p)
            self.assertIsInstance(parsed, list)

    def test_nuxt_island_path_regex(self):
        from burpsuite_mcp.tools.nuxt_island_probe import _ISLAND_PATH_RE
        sample = '<div data-island-uid="/__nuxt_island/UserProfile/abc123" />'
        m = _ISLAND_PATH_RE.search(sample)
        self.assertIsNotNone(m)
        self.assertTrue(m.group(0).startswith("/__nuxt_island/"))


if __name__ == "__main__":
    unittest.main()
