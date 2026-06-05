"""W26 — Unit 42 MCP attack vectors + Unit 42 IDPI delivery methods +
DEF CON 33 WebAuthn API hijacking contexts merged into existing parent KBs."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

_KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


def _load(name: str) -> dict:
    with open(_KB / name) as h:
        return json.load(h)


class W26AiPromptInjectionAdditionsTest(unittest.TestCase):

    def setUp(self):
        self.kb = _load("ai_prompt_injection.json")

    def test_mcp_resource_theft_present(self):
        self.assertIn("mcp_resource_theft_hidden_directive_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["mcp_resource_theft_hidden_directive_2026"]
        self.assertIn("Unit 42", ctx["description"])
        self.assertIn("mcp-server", ctx["tech_match"])

    def test_mcp_conversation_hijack_present(self):
        self.assertIn("mcp_conversation_hijack_persistent_2026", self.kb["contexts"])

    def test_mcp_covert_tool_invocation_present(self):
        self.assertIn("mcp_covert_tool_invocation_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["mcp_covert_tool_invocation_2026"]
        # Critical severity — covert tool invocation = arbitrary side effects
        self.assertEqual(ctx["probes"][0]["severity"], "critical")

    def test_idpi_visual_concealment_marker_probes(self):
        self.assertIn("idpi_visual_concealment_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["idpi_visual_concealment_2026"]
        # Each probe must include a unique SWK_IDPI_* marker the matcher word-checks
        for p in ctx["probes"]:
            self.assertTrue(
                any("SWK_IDPI_" in w
                    for m in p["matchers"] for w in m.get("words", [])),
                f"probe missing SWK_IDPI marker: {p['payload'][:60]!r}"
            )

    def test_idpi_invisible_unicode_present(self):
        self.assertIn("idpi_invisible_unicode_jailbreak_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["idpi_invisible_unicode_jailbreak_2026"]
        # Payload must actually contain zero-width characters (U+200B/200C/200D/FEFF)
        payload = ctx["probes"][0]["payload"]
        zw_chars = ("​", "‌", "‍", "﻿")
        self.assertTrue(
            any(zw in payload for zw in zw_chars),
            "invisible-unicode probe must contain actual zero-width characters"
        )

    def test_idpi_payload_splitting_present(self):
        self.assertIn("idpi_payload_splitting_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["idpi_payload_splitting_2026"]
        # Payload splits across multiple HTML elements
        payload = ctx["probes"][0]["payload"]
        self.assertGreaterEqual(payload.count("<p>"), 3)


class W26OauthWebauthnHijackTest(unittest.TestCase):

    def setUp(self):
        self.kb = _load("oauth.json")

    def test_webauthn_hijack_context_present(self):
        self.assertIn("webauthn_api_hijack_jsinjection_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["webauthn_api_hijack_jsinjection_2026"]
        self.assertIn("DEF CON 33", ctx["description"])
        self.assertIn("webauthn", ctx["tech_match"])

    def test_navigator_credentials_override_probe(self):
        """Active probe must reference navigator.credentials.get/create override."""
        ctx = self.kb["contexts"]["webauthn_api_hijack_jsinjection_2026"]
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("navigator.credentials", payloads)

    def test_passive_detection_probe_marks_reference_only(self):
        ctx = self.kb["contexts"]["webauthn_api_hijack_jsinjection_2026"]
        # At least one probe is reference-only (JS-source grep)
        ref_only = [p for p in ctx["probes"]
                    if p.get("variables", {}).get("reference_only")]
        self.assertGreaterEqual(len(ref_only), 1)

    def test_critical_severity_on_active_collab_probe(self):
        """Active variant (Collaborator-exfil challenge) is CRITICAL severity."""
        ctx = self.kb["contexts"]["webauthn_api_hijack_jsinjection_2026"]
        collab_probes = [p for p in ctx["probes"]
                         if any(m["type"] == "collaborator" for m in p["matchers"])]
        self.assertGreaterEqual(len(collab_probes), 1)
        for p in collab_probes:
            self.assertEqual(p["severity"], "critical")


class W26KbOrgComplianceTest(unittest.TestCase):
    """Per KB-org rule: no dated/v2 sibling files created."""

    def test_no_unit42_dated_siblings(self):
        forbidden = [
            "unit42_mcp_attacks.json",
            "unit42_mcp_attacks_2026.json",
            "idpi_delivery.json",
            "indirect_prompt_injection.json",
            "webauthn_hijack.json",
            "passkey_2026.json",
        ]
        for name in forbidden:
            self.assertFalse(
                (_KB / name).exists(),
                f"KB-org rule violation: dated/v2 sibling {name} must not exist"
            )


if __name__ == "__main__":
    unittest.main()
