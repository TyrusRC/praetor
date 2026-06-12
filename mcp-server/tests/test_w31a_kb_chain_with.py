"""W31-a — 10 KB files carry chain_with[] for chain reasoning."""
import json
import unittest
from pathlib import Path

KB_DIR = Path(__file__).parent.parent / "src" / "burpsuite_mcp" / "knowledge"

KB_CHAIN_SETS = {
    "open_redirect.json":   {"oauth", "dom_xss", "info_disclosure", "csrf"},
    "csrf.json":            {"xss", "dom_xss", "account_takeover", "mfa_bypass", "oauth"},
    "info_disclosure.json": {"jwt", "ssrf", "idor", "cve", "auth_bypass"},
    "cors.json":            {"csrf", "account_takeover", "idor", "info_disclosure"},
    "host_header.json":     {"cache_poisoning", "ssrf", "password_reset_poisoning", "open_redirect"},
    "clickjacking.json":    {"csrf", "account_takeover", "ui_redress"},
    "dom_xss.json":         {"postmessage_xss", "oauth", "csrf", "account_takeover", "webauthn_api_hijack"},
    "oauth.json":           {"open_redirect", "csrf", "passkey_stepup_bypass", "account_takeover", "saml_xsw"},
    "idor.json":            {"mass_assignment", "business_logic", "info_disclosure", "bfla"},
    "jwt.json":             {"idor", "bfla", "oauth", "account_takeover", "info_disclosure"},
}


class ChainWithFieldTest(unittest.TestCase):
    def test_all_present_and_non_empty(self):
        for name, expected in KB_CHAIN_SETS.items():
            p = KB_DIR / name
            self.assertTrue(p.exists(), f"{name} missing")
            data = json.loads(p.read_text())
            self.assertIn("chain_with", data, f"{name} missing chain_with field")
            actual = set(data["chain_with"])
            self.assertTrue(
                expected.issubset(actual),
                f"{name} chain_with missing: {expected - actual}",
            )

    def test_chain_with_is_list_of_str(self):
        for name in KB_CHAIN_SETS:
            data = json.loads((KB_DIR / name).read_text())
            cw = data["chain_with"]
            self.assertIsInstance(cw, list)
            for entry in cw:
                self.assertIsInstance(entry, str)
                self.assertGreater(len(entry), 0)

    def test_loader_still_parses(self):
        """Adding top-level chain_with must not break the KB loader."""
        from burpsuite_mcp.tools.scan._helpers import _load_knowledge
        for name in KB_CHAIN_SETS:
            cat = name.replace(".json", "")
            kb = _load_knowledge(cat)
            self.assertIsNotNone(kb, f"{cat} did not load")
            self.assertIn("contexts", kb)


if __name__ == "__main__":
    unittest.main()
