"""All 10 new KB files load + parse + carry the required schema."""
import json
import unittest
from pathlib import Path

KB_DIR = Path(__file__).parent.parent / "src" / "burpsuite_mcp" / "knowledge"

NEW_FILES = [
    "state_machine_race.json",
    "oauth_dpop_confused_deputy.json",
    "edge_worker_ssrf.json",
    "webauthn_passkey_attacks.json",
    "cache_deception_v2.json",
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


if __name__ == "__main__":
    unittest.main()
