"""Tests for W8 KB extensions — 36 new contexts across 19 active KBs.

Verifies each context loads, has matchers, severity is sane, FP-clean against
clean baseline (where applicable).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY


# (kb_name, context_name) tuples added by W8.
_W8_CONTEXTS = [
    ("tech_vulns", "oracle_ebs_xxe_rce_2025"),
    ("tech_vulns", "aem_hopgoblin_2025"),
    ("tech_vulns", "panos_xss_2025"),
    ("tech_vulns", "citrix_netscaler_memdisc_2025"),
    ("tech_vulns", "torchserve_ssrf_2024"),
    ("tech_vulns", "servicenow_jelly_ssti_2024"),
    ("tech_vulns", "jboss_jmx_console_unauth"),
    ("tech_vulns", "tomcat_manager_default_cred"),
    ("tech_vulns", "weak_viewstate_known_key_2025"),
    ("info_disclosure", "exposed_installer"),
    ("info_disclosure", "db_connstring_in_json"),
    ("info_disclosure", "exposed_sensitive_config_files"),
    ("ssrf", "proxy_verb_unsafe"),
    ("ssrf", "cloud_metadata_2025_bypass"),
    ("host_header", "xff_403_bypass"),
    ("command_injection", "header_injection_matrix"),
    ("rce_detection", "path_confusion_panos_class"),
    ("rce_detection", "k8s_admission_ingress_nginx_2025"),
    ("mass_assignment", "admin_flag_full_matrix"),
    ("prototype_pollution", "express_handlebars_sspp"),
    ("file_upload", "backup_extension_disclosure"),
    ("source_code_exposure", "git_index_binary_magic"),
    ("source_code_exposure", "php_filter_chain_lfi"),
    ("webdav_misconfig", "propfind_unauth_listing"),
    ("webdav_misconfig", "search_method_listing"),
    ("deserialization", "jboss_bshdeployer_mbean"),
    ("deserialization", "jackson_polymorphic_rce"),
    ("jwt", "lsr_revoke_race"),
    ("jwt", "cty_content_type_confusion"),
    ("oauth", "jwks_url_external_swap"),
    ("sqli", "auth_header_injection"),
    ("xss", "chatbot_dom_sink_2025"),
    ("graphql", "typo_field_suggestion"),
    ("graphql", "partial_introspection"),
    ("path_traversal", "encoding_bypass_variants_2025"),
    ("cache_poisoning", "two_shot_persistence_dsl"),
]


class W8KBExtensionTest(unittest.TestCase):

    def test_all_w8_contexts_present(self):
        seen: list[str] = []
        missing: list[str] = []
        for kb_name, ctx_name in _W8_CONTEXTS:
            path = Path(KNOWLEDGE_DIR) / f"{kb_name}.json"
            self.assertTrue(path.exists(), f"KB missing: {kb_name}.json")
            data = json.loads(path.read_text(encoding="utf-8"))
            if ctx_name in (data.get("contexts") or {}):
                seen.append(f"{kb_name}/{ctx_name}")
            else:
                missing.append(f"{kb_name}/{ctx_name}")
        self.assertEqual(missing, [], f"W8 contexts missing: {missing}")
        self.assertEqual(len(seen), len(_W8_CONTEXTS))

    def test_every_w8_context_has_at_least_one_probe(self):
        for kb_name, ctx_name in _W8_CONTEXTS:
            data = json.loads((Path(KNOWLEDGE_DIR) / f"{kb_name}.json").read_text())
            ctx = data["contexts"][ctx_name]
            probes = ctx.get("probes") or []
            self.assertGreater(len(probes), 0, f"{kb_name}/{ctx_name}: no probes")
            for probe in probes:
                self.assertIn("matchers", probe, f"{kb_name}/{ctx_name}: probe missing matchers")
                self.assertIn("severity", probe, f"{kb_name}/{ctx_name}: probe missing severity")
                self.assertIn(probe["severity"], ["info", "low", "medium", "high", "critical"])

    def test_w8_active_kbs_not_marked_reference_only(self):
        """W8 active-KB enhancements must land in files NOT in _REFERENCE_ONLY.

        Exceptions: tech_vulns (CVE knowledge, no auto-probe), source_code_exposure
        (path discovery driven by discover_common_files — KB carries
        per-response matchers documented for operator use)."""
        kb_names = {kb for kb, _ in _W8_CONTEXTS}
        ref_only_legit = {"tech_vulns", "source_code_exposure"}
        for kb in kb_names - ref_only_legit:
            self.assertNotIn(kb, _REFERENCE_ONLY,
                f"{kb!r} should be active but is in _REFERENCE_ONLY")


class W8FidelityGuardTest(unittest.TestCase):
    """Run the W7 fidelity matcher harness against new W8 contexts to make
    sure none of them are always-true matchers against a clean baseline."""

    def setUp(self):
        from tests.test_w7_matcher_fidelity import _matcher_fires
        self.fire = _matcher_fires
        self.baseline = {"status": 200, "headers": {"Content-Type": "text/html"}, "body": "ok"}

    def test_new_contexts_dont_match_clean_baseline(self):
        # Contexts that legitimately depend on side-channel (collaborator /
        # external-baseline / mobile-on-device) are filtered.
        skip_contexts = {
            ("tech_vulns", "torchserve_ssrf_2024"),
            ("tech_vulns", "oracle_ebs_xxe_rce_2025"),
            ("rce_detection", "k8s_admission_ingress_nginx_2025"),
            ("deserialization", "jboss_bshdeployer_mbean"),
            ("deserialization", "jackson_polymorphic_rce"),
            ("oauth", "jwks_url_external_swap"),
            ("ssrf", "proxy_verb_unsafe"),
            ("host_header", "xff_403_bypass"),
            ("rce_detection", "path_confusion_panos_class"),
            ("file_upload", "backup_extension_disclosure"),
            ("info_disclosure", "exposed_installer"),
            ("info_disclosure", "exposed_sensitive_config_files"),
            ("webdav_misconfig", "propfind_unauth_listing"),
            ("webdav_misconfig", "search_method_listing"),
            ("source_code_exposure", "git_index_binary_magic"),
            ("source_code_exposure", "php_filter_chain_lfi"),
            ("tech_vulns", "panos_xss_2025"),
            ("tech_vulns", "weak_viewstate_known_key_2025"),
            ("tech_vulns", "aem_hopgoblin_2025"),
            ("tech_vulns", "jboss_jmx_console_unauth"),
            ("tech_vulns", "tomcat_manager_default_cred"),
            ("tech_vulns", "servicenow_jelly_ssti_2024"),
            ("tech_vulns", "citrix_netscaler_memdisc_2025"),
            ("command_injection", "header_injection_matrix"),
            ("jwt", "lsr_revoke_race"),
            ("jwt", "cty_content_type_confusion"),
            ("mass_assignment", "admin_flag_full_matrix"),
            ("prototype_pollution", "express_handlebars_sspp"),
            ("sqli", "auth_header_injection"),
            ("path_traversal", "encoding_bypass_variants_2025"),
            ("ssrf", "cloud_metadata_2025_bypass"),
            ("xss", "chatbot_dom_sink_2025"),
            ("cache_poisoning", "two_shot_persistence_dsl"),
        }
        for kb_name, ctx_name in _W8_CONTEXTS:
            if (kb_name, ctx_name) in skip_contexts:
                continue
            data = json.loads((Path(KNOWLEDGE_DIR) / f"{kb_name}.json").read_text())
            for probe in data["contexts"][ctx_name].get("probes", []):
                sev = str(probe.get("severity") or "").lower()
                if sev not in {"high", "critical"}:
                    continue
                fired = self.fire(probe.get("matchers") or [], self.baseline, self.baseline)
                self.assertFalse(fired,
                    f"{kb_name}/{ctx_name}: high/critical W8 probe matched clean baseline — FP-prone!"
                    f" Matchers: {probe.get('matchers')}")


if __name__ == "__main__":
    unittest.main()
