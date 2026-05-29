"""W18 — 2025 H2 CVE KB expansion: cache_poisoning + graphql + oauth."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR


_W18_CONTEXTS = [
    ("cache_poisoning", "nextjs_15_cache_key_confusion"),
    ("graphql", "subscription_protocol_drift_2025"),
    ("graphql", "subscription_auth_skip_legacy_protocol"),
    ("oauth", "par_request_uri_attacker_controlled_2025"),
    ("oauth", "dpop_nonce_binding_skipped_2025"),
]


class W18KBExpansionTest(unittest.TestCase):

    def test_all_w18_contexts_present(self):
        for kb_name, ctx_name in _W18_CONTEXTS:
            path = Path(KNOWLEDGE_DIR) / f"{kb_name}.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(ctx_name, data.get("contexts", {}),
                          f"W18 ctx missing: {kb_name}/{ctx_name}")

    def test_every_w18_context_has_probes(self):
        for kb_name, ctx_name in _W18_CONTEXTS:
            data = json.loads(
                (Path(KNOWLEDGE_DIR) / f"{kb_name}.json").read_text(encoding="utf-8")
            )
            ctx = data["contexts"][ctx_name]
            probes = ctx.get("probes", [])
            self.assertGreater(len(probes), 0,
                               f"{kb_name}/{ctx_name}: no probes")
            for probe in probes:
                self.assertIn("matchers", probe,
                              f"{kb_name}/{ctx_name}: probe missing matchers")
                self.assertIn("severity", probe,
                              f"{kb_name}/{ctx_name}: probe missing severity")
                self.assertIn(probe["severity"],
                              ["info", "low", "medium", "high", "critical"])

    def test_nextjs_context_specifics(self):
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "cache_poisoning.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["nextjs_15_cache_key_confusion"]
        # Should reference Next.js / Vercel tech_match.
        tech = " ".join(ctx.get("tech_match", [])).lower()
        self.assertTrue("next" in tech or "vercel" in tech,
                        f"nextjs ctx missing tech_match: {tech}")

    def test_oauth_par_uses_collaborator(self):
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "oauth.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["par_request_uri_attacker_controlled_2025"]
        # Should use collaborator matcher (verifies attacker-URI fetch).
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        self.assertIn("collaborator", types,
                      "PAR ctx should verify attacker-URI fetch via collaborator")

    def test_graphql_subscription_drift_websocket_signal(self):
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "graphql.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["subscription_protocol_drift_2025"]
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        # Should look for WS upgrade status (101) and protocol header.
        self.assertIn("status", types)
        self.assertIn("header", types)


if __name__ == "__main__":
    unittest.main()
