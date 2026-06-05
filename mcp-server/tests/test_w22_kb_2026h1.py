"""W22 — 2026 H1 CVE KB expansion: LangGrinch / OpenNext SSRF / Claude Code CVEs."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR


_W22_CONTEXTS = [
    ("ai_prompt_injection", "langchain_lc_marker_injection_2025"),
    ("edge_worker_ssrf", "opennext_cloudflare_cdn_cgi_backslash_norm_2026"),
    ("mcp_server_attacks", "claude_code_path_prefix_match_traversal_2025"),
    ("mcp_server_attacks", "claude_code_tool_arg_shell_injection_2025"),
    ("mcp_server_attacks", "claude_code_settings_json_hook_preconsent_rce_2025"),
    # W22-b CUA injection surface contexts
    ("ai_prompt_injection", "cua_dom_hidden_instruction_2026"),
    ("ai_prompt_injection", "cua_multistep_persistence_2026"),
    ("ai_prompt_injection", "cua_data_attribute_pii_2026"),
]


class W22KBExpansionTest(unittest.TestCase):

    def test_all_w22_contexts_present(self):
        for kb_name, ctx_name in _W22_CONTEXTS:
            path = Path(KNOWLEDGE_DIR) / f"{kb_name}.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(ctx_name, data.get("contexts", {}),
                          f"W22 ctx missing: {kb_name}/{ctx_name}")

    def test_every_w22_context_has_probes(self):
        for kb_name, ctx_name in _W22_CONTEXTS:
            data = json.loads(
                (Path(KNOWLEDGE_DIR) / f"{kb_name}.json").read_text(encoding="utf-8")
            )
            ctx = data["contexts"][ctx_name]
            probes = ctx.get("probes", [])
            self.assertGreater(len(probes), 0, f"{kb_name}/{ctx_name}: no probes")
            for probe in probes:
                self.assertIn("matchers", probe)
                self.assertIn("severity", probe)
                self.assertIn(probe["severity"],
                              ["info", "low", "medium", "high", "critical"])

    def test_langgrinch_collaborator_or_reflective(self):
        """LangGrinch detection ladder: OOB (collaborator) OR reflective canary."""
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "ai_prompt_injection.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["langchain_lc_marker_injection_2025"]
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        # Needs both pathways: out-of-band confirmation AND a reflective fallback.
        self.assertIn("collaborator", types,
                      "LangGrinch ctx missing collaborator pathway")
        self.assertIn("word", types,
                      "LangGrinch ctx missing reflective-canary pathway")
        # Payload must carry the lc marker key shape.
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("\"lc\":1", payloads)
        self.assertIn("constructor", payloads)
        self.assertIn("langchain_core", payloads)

    def test_opennext_backslash_variants_present(self):
        """Must probe raw \\ AND %5C variants — different edge proxies normalise differently."""
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "edge_worker_ssrf.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["opennext_cloudflare_cdn_cgi_backslash_norm_2026"]
        payloads = [p["payload"] for p in ctx["probes"]]
        self.assertTrue(any("\\image" in p for p in payloads),
                        "OpenNext ctx missing raw backslash variant")
        self.assertTrue(any("%5C" in p for p in payloads),
                        "OpenNext ctx missing URL-encoded backslash variant")
        # Cloudflare-specific evidence: cf-ray header matcher.
        headers = [h for p in ctx["probes"]
                   for m in p["matchers"]
                   for h in m.get("headers", [])]
        self.assertIn("cf-ray", headers)

    def test_claude_code_cves_marked_reference_only(self):
        """Claude Code CVEs are filesystem/static — must be reference_only (not auto_probe-active)."""
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "mcp_server_attacks.json").read_text(encoding="utf-8")
        )
        for ctx_name in (
            "claude_code_path_prefix_match_traversal_2025",
            "claude_code_tool_arg_shell_injection_2025",
            "claude_code_settings_json_hook_preconsent_rce_2025",
        ):
            ctx = data["contexts"][ctx_name]
            for probe in ctx["probes"]:
                self.assertTrue(
                    probe.get("variables", {}).get("reference_only", False),
                    f"{ctx_name}: probe must be reference_only (static/FS class)",
                )

    def test_claude_code_hook_ctx_detects_hook_keys(self):
        """Hook-injection ctx must match PreToolUse/PostToolUse/hooks/mcpServers keys."""
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "mcp_server_attacks.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["claude_code_settings_json_hook_preconsent_rce_2025"]
        regexes = [m.get("pattern", "") for p in ctx["probes"]
                   for m in p["matchers"] if m["type"] == "regex"]
        joined = "|".join(regexes)
        self.assertIn("hooks", joined)
        self.assertIn("mcpServers", joined)


if __name__ == "__main__":
    unittest.main()
