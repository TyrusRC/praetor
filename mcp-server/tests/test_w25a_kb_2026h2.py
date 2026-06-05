"""W25-a — fresh 2026 H2 CVE contexts merged into existing KB parents.

Per KB-org rule: no dated/v2 sibling files. The 5 new contexts MERGE into
prototype_pollution.json (axios + n8n), mcp_server_attacks.json (mcp-atlassian
path-traversal + header-SSRF), and oauth.json (passkey step-up bypass)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

_KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


def _load(name: str) -> dict:
    with open(_KB / name) as h:
        return json.load(h)


class W25aPrototypePollutionAdditionsTest(unittest.TestCase):
    """CVE-2026-40175 (axios) + CVE-2026-44789/90/91 (n8n) → prototype_pollution.json."""

    def setUp(self):
        self.kb = _load("prototype_pollution.json")

    def test_axios_gadget_context_present(self):
        self.assertIn("axios_rce_gadget_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["axios_rce_gadget_2026"]
        self.assertIn("CVE-2026-40175", ctx["description"])
        self.assertIn("axios", ctx["tech_match"])

    def test_axios_gadget_imds_probe_exists(self):
        ctx = self.kb["contexts"]["axios_rce_gadget_2026"]
        imds_probes = [p for p in ctx["probes"]
                       if "169.254.169.254" in p["payload"]]
        self.assertEqual(len(imds_probes), 1)
        # Must have matchers for IMDS markers
        matchers = imds_probes[0]["matchers"]
        word_matchers = [m for m in matchers if m["type"] == "word"]
        self.assertTrue(any("ami-id" in m.get("words", []) for m in word_matchers))

    def test_n8n_node_context_present(self):
        self.assertIn("n8n_node_pp_rce_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["n8n_node_pp_rce_2026"]
        self.assertIn("CVE-2026-44789", ctx["description"])
        self.assertIn("n8n", ctx["tech_match"])

    def test_n8n_probe_uses_collaborator(self):
        ctx = self.kb["contexts"]["n8n_node_pp_rce_2026"]
        # At least one probe with Collaborator matcher
        has_collab = any(
            any(m["type"] == "collaborator" for m in p["matchers"])
            for p in ctx["probes"]
        )
        self.assertTrue(has_collab, "n8n probe set must include Collaborator-confirmed variant")


class W25aMcpAtlassianAdditionsTest(unittest.TestCase):
    """CVE-2026-27825 (path traversal) + CVE-2026-27826 (header SSRF) → mcp_server_attacks.json."""

    def setUp(self):
        self.kb = _load("mcp_server_attacks.json")

    def test_path_traversal_context_present(self):
        self.assertIn("mcp_atlassian_path_traversal_rce_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["mcp_atlassian_path_traversal_rce_2026"]
        self.assertIn("CVE-2026-27825", ctx["description"])

    def test_path_traversal_has_linux_and_windows_canaries(self):
        ctx = self.kb["contexts"]["mcp_atlassian_path_traversal_rce_2026"]
        payloads = [p["payload"] for p in ctx["probes"]]
        # Both LFI flavours present
        self.assertTrue(any("/etc/passwd" in p for p in payloads))
        self.assertTrue(any("win.ini" in p.lower() for p in payloads))

    def test_header_ssrf_context_present(self):
        self.assertIn("mcp_atlassian_header_ssrf_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["mcp_atlassian_header_ssrf_2026"]
        self.assertIn("CVE-2026-27826", ctx["description"])

    def test_header_ssrf_uses_atlassian_headers(self):
        ctx = self.kb["contexts"]["mcp_atlassian_header_ssrf_2026"]
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("X-Atlassian-Jira-Url", payloads)
        self.assertIn("X-Atlassian-Confluence-Url", payloads)


class W25aOauthPasskeyAdditionsTest(unittest.TestCase):
    """CVE-2026-32879 (passkey step-up bypass) → oauth.json."""

    def setUp(self):
        self.kb = _load("oauth.json")

    def test_passkey_stepup_context_present(self):
        self.assertIn("passkey_stepup_no_assertion_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["passkey_stepup_no_assertion_2026"]
        self.assertIn("CVE-2026-32879", ctx["description"])

    def test_canonical_bypass_payload_present(self):
        ctx = self.kb["contexts"]["passkey_stepup_no_assertion_2026"]
        # The canonical bypass: {"method":"passkey"} with no assertion
        canonical = [p for p in ctx["probes"]
                     if p["payload"].strip() == '{"method":"passkey"}']
        self.assertEqual(len(canonical), 1)

    def test_tech_match_includes_webauthn_family(self):
        ctx = self.kb["contexts"]["passkey_stepup_no_assertion_2026"]
        for required in ("webauthn", "passkey", "fido2"):
            self.assertIn(required, ctx["tech_match"])

    def test_session_precondition_documented(self):
        """Probe must declare requires_authenticated_session so callers
        know to attach a real session before firing."""
        ctx = self.kb["contexts"]["passkey_stepup_no_assertion_2026"]
        for p in ctx["probes"]:
            self.assertTrue(
                p.get("variables", {}).get("requires_authenticated_session"),
                f"probe {p['payload'][:40]!r} missing requires_authenticated_session"
            )


class W25aKbOrgRuleComplianceTest(unittest.TestCase):
    """Per CLAUDE.md KB-organization rule: no dated/v2 sibling files."""

    def test_no_dated_sibling_files_created(self):
        # The 5 new contexts should NOT appear as standalone files
        forbidden = [
            "prototype_pollution_2026.json",
            "prototype_pollution_v2.json",
            "mcp_atlassian.json",
            "passkey.json",
            "passkey_stepup.json",
            "oauth_2026.json",
            "oauth_v2.json",
        ]
        for name in forbidden:
            self.assertFalse(
                (_KB / name).exists(),
                f"KB-org rule violation: dated/v2 sibling {name} must not exist"
            )


if __name__ == "__main__":
    unittest.main()
