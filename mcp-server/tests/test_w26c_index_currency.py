"""W26-c — _INDEX.md must reference W22-W26 KB additions so operator-driven
lookups via the prefix loader find them. Without this, new contexts merge
into JSON files but stay invisible to recall workflows that consult the
index summary."""

from __future__ import annotations

import unittest
from pathlib import Path

_KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"
_INDEX = _KB / "_INDEX.md"


def _read_index() -> str:
    return _INDEX.read_text()


class IndexReferencesW22Through26AdditionsTest(unittest.TestCase):
    """Each W22-W26 KB addition MUST be name-referenced in _INDEX.md, otherwise
    the operator-driven recall workflows skip it. Extending existing rows is
    the canonical pattern; dated/v2 sibling sections in the index are
    forbidden by the same KB-org rule."""

    def setUp(self):
        self.idx = _read_index()

    # ── W22-a additions ──
    def test_langgrinch_referenced(self):
        self.assertIn("langchain_lc_marker_injection_2025", self.idx)

    def test_opennext_referenced(self):
        self.assertIn("opennext_cloudflare_cdn_cgi_backslash_norm_2026", self.idx)

    def test_claude_code_cves_referenced(self):
        for ctx in (
            "claude_code_path_prefix_match_traversal_2025",
            "claude_code_tool_arg_shell_injection_2025",
            "claude_code_settings_json_hook_preconsent_rce_2025",
        ):
            self.assertIn(ctx, self.idx)

    # ── W22-b additions ──
    def test_cua_contexts_referenced(self):
        for ctx in (
            "cua_dom_hidden_instruction_2026",
            "cua_multistep_persistence_2026",
            "cua_data_attribute_pii_2026",
        ):
            self.assertIn(ctx, self.idx)

    # ── W25-a additions ──
    def test_axios_pp_gadget_referenced(self):
        self.assertIn("axios_rce_gadget_2026", self.idx)
        self.assertIn("CVE-2026-40175", self.idx)

    def test_n8n_node_pp_referenced(self):
        self.assertIn("n8n_node_pp_rce_2026", self.idx)

    def test_mcp_atlassian_cves_referenced(self):
        for ctx in (
            "mcp_atlassian_path_traversal_rce_2026",
            "mcp_atlassian_header_ssrf_2026",
        ):
            self.assertIn(ctx, self.idx)
        self.assertIn("CVE-2026-27825", self.idx)
        self.assertIn("CVE-2026-27826", self.idx)

    def test_passkey_stepup_referenced(self):
        self.assertIn("passkey_stepup_no_assertion_2026", self.idx)
        self.assertIn("CVE-2026-32879", self.idx)

    # ── W26 additions ──
    def test_unit42_mcp_attack_vectors_referenced(self):
        for ctx in (
            "mcp_resource_theft_hidden_directive_2026",
            "mcp_conversation_hijack_persistent_2026",
            "mcp_covert_tool_invocation_2026",
        ):
            self.assertIn(ctx, self.idx)

    def test_unit42_idpi_delivery_referenced(self):
        for ctx in (
            "idpi_visual_concealment_2026",
            "idpi_invisible_unicode_jailbreak_2026",
            "idpi_payload_splitting_2026",
        ):
            self.assertIn(ctx, self.idx)

    def test_webauthn_api_hijack_referenced(self):
        self.assertIn("webauthn_api_hijack_jsinjection_2026", self.idx)
        self.assertIn("DEF CON 33", self.idx)


class IndexKbOrgComplianceTest(unittest.TestCase):
    """Index must extend existing rows; no dated/v2 section additions
    per the KB-organization rule."""

    def test_no_2026_h2_additions_section(self):
        """Operator preference: no '## 2026-MM-DD additions' sections.
        New contexts extend existing rows in-place."""
        idx = _read_index()
        # Allow the historical sections W7+ added, but no new ones for W22+
        forbidden_headers = (
            "## W22 additions",
            "## W23 additions",
            "## W24 additions",
            "## W25 additions",
            "## W26 additions",
            "## 2026-06-05 additions",
            "## 2026 H2 additions",
        )
        for h in forbidden_headers:
            self.assertNotIn(h, idx,
                             f"KB-org rule violation: {h!r} section in _INDEX.md")


if __name__ == "__main__":
    unittest.main()
