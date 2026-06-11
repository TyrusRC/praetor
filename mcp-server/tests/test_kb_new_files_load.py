"""All 10 new KB files load + parse + carry the required schema."""
import json
import unittest
from pathlib import Path

KB_DIR = Path(__file__).parent.parent / "src" / "burpsuite_mcp" / "knowledge"

NEW_FILES = [
    "state_machine_race.json",
    "oauth_dpop_confused_deputy.json",
    "edge_worker_ssrf.json",
    # W29-i (2026-06-11): webauthn_passkey_attacks merged into webauthn_passkey
    # and cache_deception_v2 merged into web_cache_deception per KB-org rule
    "webauthn_passkey.json",
    "web_cache_deception.json",
    "dom_clobbering_2024.json",
    "service_worker_attacks.json",
    "h2_continuation_flood.json",
    "mcp_server_attacks.json",
    "rag_injection.json",
]


class KbNewFilesLoadTest(unittest.TestCase):
    def test_all_parse(self):
        for name in NEW_FILES:
            p = KB_DIR / name
            self.assertTrue(p.exists(), f"{name} missing")
            data = json.loads(p.read_text())
            self.assertIn("category", data, f"{name} missing 'category'")
            self.assertIn("contexts", data, f"{name} missing 'contexts'")
            self.assertGreater(len(data["contexts"]), 0, f"{name} has empty contexts")
            for ctx_name, ctx in data["contexts"].items():
                self.assertIn("probes", ctx, f"{name}:{ctx_name} missing probes")
                for probe in ctx["probes"]:
                    self.assertIn("payload", probe)
                    self.assertIn("matchers", probe)


class ReferenceOnlySkipsAutoProbeTest(unittest.TestCase):
    def test_dos_reference_only_in_set(self):
        # DoS-class KBs stay reference-only per Rule 5.
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        for name in ("h2_continuation_flood",):
            self.assertIn(name, _REFERENCE_ONLY, f"{name} should be reference-only")

    def test_seven_auto_probe_NOT_in_reference_only(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        # As of Praetor v1.0 (Wave 5) mcp_server_attacks + rag_injection were
        # promoted out of reference-only into active auto_probe. Verify here.
        # W29-i (2026-06-11): webauthn_passkey_attacks contexts merged INTO
        # webauthn_passkey parent; cache_deception_v2 contexts merged INTO
        # web_cache_deception parent. The merged-into parents take their place.
        for name in ("state_machine_race", "oauth_dpop_confused_deputy",
                     "edge_worker_ssrf", "webauthn_passkey",
                     "dom_clobbering_2024",
                     "service_worker_attacks",
                     "mcp_server_attacks", "rag_injection"):
            self.assertNotIn(name, _REFERENCE_ONLY, f"{name} must be auto-probe enabled")


if __name__ == "__main__":
    unittest.main()
