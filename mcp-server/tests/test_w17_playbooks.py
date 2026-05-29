"""W17 — 3 new deep-dive playbooks + router integration."""

from __future__ import annotations

import unittest
from pathlib import Path


def _read_skill(name: str) -> str:
    p = Path(f"../.claude/skills/{name}")
    if not p.exists():
        p = Path(f".claude/skills/{name}")
    return p.read_text(encoding="utf-8") if p.exists() else ""


class OAuthPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-oauth-flow-attacks.md")
        self.assertGreater(len(content), 1500, "OAuth playbook missing or too small")

    def test_flow_inventory_present(self):
        content = _read_skill("playbook-oauth-flow-attacks.md")
        for flow in ("Authorization Code", "PKCE", "Device Code",
                     "Client Credentials", "Hybrid"):
            self.assertIn(flow, content, f"OAuth flow missing: {flow}")

    def test_attacks_present(self):
        content = _read_skill("playbook-oauth-flow-attacks.md")
        for attack in ("redirect_uri quirks", "Mix-up attack",
                       "PKCE downgrade", "PAR (Pushed Authorization Requests",
                       "DPoP"):
            self.assertIn(attack, content, f"OAuth attack missing: {attack}")

    def test_chain_to_jwt_playbook(self):
        content = _read_skill("playbook-oauth-flow-attacks.md")
        self.assertIn("playbook-jwt-deep-dive.md", content,
                      "OAuth playbook should reference JWT playbook for token-level attacks")


class RequestSmugglingPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-request-smuggling.md")
        self.assertGreater(len(content), 1500, "smuggling playbook missing or too small")

    def test_classic_variants_present(self):
        content = _read_skill("playbook-request-smuggling.md")
        for variant in ("CL.TE", "TE.CL", "TE.TE"):
            self.assertIn(variant, content, f"classic variant missing: {variant}")

    def test_kettle_2025_endgame_present(self):
        content = _read_skill("playbook-request-smuggling.md")
        for variant in ("0.CL", "CL.0", "V-H", "Expect", "RQP", "double-desync"):
            self.assertIn(variant, content, f"Kettle 2025 variant missing: {variant}")

    def test_cve_2025_32094_referenced(self):
        content = _read_skill("playbook-request-smuggling.md")
        self.assertIn("CVE-2025-32094", content)
        self.assertIn("Akamai", content)

    def test_references_tools(self):
        content = _read_skill("playbook-request-smuggling.md")
        for tool in ("test_request_smuggling", "run_smuggle"):
            self.assertIn(tool, content, f"smuggling playbook missing tool: {tool}")


class PrototypePollutionPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-prototype-pollution.md")
        self.assertGreater(len(content), 1500, "PP playbook missing or too small")

    def test_cspp_sspp_distinction(self):
        content = _read_skill("playbook-prototype-pollution.md")
        self.assertIn("CSPP", content)
        self.assertIn("SSPP", content)
        self.assertIn("Client-Side Prototype Pollution", content)
        self.assertIn("Server-Side Prototype Pollution", content)

    def test_sinks_documented(self):
        content = _read_skill("playbook-prototype-pollution.md")
        for sink in ("child_process", "exec_argv", "isAdmin",
                     "DOMPurify", "Express", "Fastify", "Hapi",
                     "Handlebars"):
            self.assertIn(sink, content, f"PP sink missing: {sink}")

    def test_references_tools(self):
        content = _read_skill("playbook-prototype-pollution.md")
        for tool in ("test_prototype_pollution", "test_dom_sinks"):
            self.assertIn(tool, content, f"PP playbook missing tool: {tool}")

    def test_cve_referenced(self):
        content = _read_skill("playbook-prototype-pollution.md")
        self.assertIn("CVE-2024-21509", content)


class RouterUpdateTest(unittest.TestCase):

    def test_router_lists_all_w16_w17_deep_dives(self):
        content = _read_skill("playbook-router.md")
        for playbook in (
            "playbook-ssrf-deep-dive.md",
            "playbook-idor-bola.md",
            "playbook-jwt-deep-dive.md",
            "playbook-oauth-flow-attacks.md",
            "playbook-request-smuggling.md",
            "playbook-prototype-pollution.md",
        ):
            self.assertIn(playbook, content, f"router missing deep-dive: {playbook}")

    def test_router_distinguishes_deep_dives_from_primary(self):
        content = _read_skill("playbook-router.md")
        self.assertIn("Per-vuln-class deep-dives", content,
                      "router needs a section explaining deep-dives vs primary playbooks")
        self.assertIn("Loading rule:", content,
                      "router should document the load-when-investigating rule")


if __name__ == "__main__":
    unittest.main()
