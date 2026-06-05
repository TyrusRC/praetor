"""W28-b — 2026 H2 mid-year CVE intake (June 2026 disclosures + Black Hat USA 2026).

Merges into existing parent KBs per the KB-org rule (no dated/v2 sibling files).
Currency tests assert each new context name AND its CVE/source reference
appear both in the parent JSON and in _INDEX.md."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

_KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


def _load(name: str) -> dict:
    with open(_KB / name) as h:
        return json.load(h)


def _index() -> str:
    return (_KB / "_INDEX.md").read_text()


class W28bEdgeWorkerSsrfAddition(unittest.TestCase):
    """CVE-2026-44578 — Next.js WebSocket-upgrade SSRF."""

    def setUp(self):
        self.kb = _load("edge_worker_ssrf.json")

    def test_context_present(self):
        self.assertIn("nextjs_websocket_upgrade_ssrf_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["nextjs_websocket_upgrade_ssrf_2026"]
        self.assertIn("CVE-2026-44578", ctx["description"])
        self.assertIn("next.js", ctx["tech_match"])

    def test_imds_probe_targets_169_254(self):
        ctx = self.kb["contexts"]["nextjs_websocket_upgrade_ssrf_2026"]
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("169.254.169.254", payloads)
        self.assertIn("Upgrade: websocket", payloads)

    def test_index_referenced(self):
        self.assertIn("nextjs_websocket_upgrade_ssrf_2026", _index())
        self.assertIn("CVE-2026-44578", _index())


class W28bDeserializationAddition(unittest.TestCase):
    """CVE-2026-45247 (KEV active) — Magento Mirasvit PHP unserialize RCE."""

    def setUp(self):
        self.kb = _load("deserialization.json")

    def test_context_present(self):
        self.assertIn("magento_mirasvit_php_unserialize_rce_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["magento_mirasvit_php_unserialize_rce_2026"]
        self.assertIn("CVE-2026-45247", ctx["description"])
        self.assertIn("KEV", ctx["description"])

    def test_critical_severity_on_gadget_probe(self):
        ctx = self.kb["contexts"]["magento_mirasvit_php_unserialize_rce_2026"]
        gadget = [p for p in ctx["probes"]
                  if any(m["type"] == "collaborator" for m in p["matchers"])]
        self.assertEqual(len(gadget), 1)
        self.assertEqual(gadget[0]["severity"], "critical")

    def test_index_referenced(self):
        self.assertIn("magento_mirasvit_php_unserialize_rce_2026", _index())
        self.assertIn("CVE-2026-45247", _index())


class W28bWebsocketAddition(unittest.TestCase):
    """CVE-2026-39987 — Marimo pre-auth WebSocket terminal RCE."""

    def setUp(self):
        self.kb = _load("websocket.json")

    def test_context_present(self):
        self.assertIn("marimo_websocket_terminal_rce_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["marimo_websocket_terminal_rce_2026"]
        self.assertIn("CVE-2026-39987", ctx["description"])
        self.assertIn("marimo", ctx["tech_match"])

    def test_uid_regex_matcher(self):
        """Confirmation matcher must look for shell uid= output (real RCE proof)."""
        ctx = self.kb["contexts"]["marimo_websocket_terminal_rce_2026"]
        regex_matchers = [m for p in ctx["probes"]
                          for m in p["matchers"] if m["type"] == "regex"]
        self.assertTrue(any("uid=" in m.get("pattern", "")
                            for m in regex_matchers))

    def test_index_referenced(self):
        self.assertIn("marimo_websocket_terminal_rce_2026", _index())


class W28bSourceExposureAddition(unittest.TestCase):
    """CVE-2026-39365 — Vite dev-server path traversal via optimized-deps .map."""

    def setUp(self):
        self.kb = _load("source_code_exposure.json")

    def test_context_present(self):
        self.assertIn("vite_devserver_optimized_deps_path_traversal_2026",
                      self.kb["contexts"])
        ctx = self.kb["contexts"]["vite_devserver_optimized_deps_path_traversal_2026"]
        self.assertIn("CVE-2026-39365", ctx["description"])
        self.assertIn("vite", ctx["tech_match"])

    def test_traversal_payload_targets_node_modules_vite_deps(self):
        ctx = self.kb["contexts"]["vite_devserver_optimized_deps_path_traversal_2026"]
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("/node_modules/.vite/deps", payloads)
        self.assertIn("../", payloads)

    def test_index_referenced(self):
        self.assertIn("vite_devserver_optimized_deps_path_traversal_2026", _index())


class W28bAiPromptInjectionAddition(unittest.TestCase):
    """Black Hat USA 2026 'Beyond Normalization' — illegal-UTF8 jailbreak."""

    def setUp(self):
        self.kb = _load("ai_prompt_injection.json")

    def test_context_present(self):
        self.assertIn("idpi_illegal_utf8_normalization_2026", self.kb["contexts"])
        ctx = self.kb["contexts"]["idpi_illegal_utf8_normalization_2026"]
        self.assertIn("Black Hat USA 2026", ctx["description"])

    def test_overlong_utf8_payload_present(self):
        ctx = self.kb["contexts"]["idpi_illegal_utf8_normalization_2026"]
        # The overlong encoding 0xc0 0xae is encoded in the JSON as \\xc0\\xae
        # (literal backslashes) because JSON can't carry raw bytes; the matcher
        # reads them as escaped sequences. Confirm the literal escape is present.
        payloads = " ".join(p["payload"] for p in ctx["probes"])
        self.assertIn("\\xc0\\xae", payloads)

    def test_index_referenced(self):
        self.assertIn("idpi_illegal_utf8_normalization_2026", _index())
        self.assertIn("Black Hat USA 2026", _index())


class W28bGraphqlAddition(unittest.TestCase):
    """HackerOne pattern — GraphQL mutation-aliasing → rate-limit bypass."""

    def setUp(self):
        self.kb = _load("graphql.json")

    def test_context_present(self):
        self.assertIn("graphql_mutation_aliasing_account_recovery_dos_2026",
                      self.kb["contexts"])
        ctx = self.kb["contexts"]["graphql_mutation_aliasing_account_recovery_dos_2026"]
        self.assertIn("rate-limit BYPASS", ctx["description"])

    def test_aliased_mutation_payload_shape(self):
        ctx = self.kb["contexts"]["graphql_mutation_aliasing_account_recovery_dos_2026"]
        # Both probes should issue ≥5 aliased mutations
        for p in ctx["probes"]:
            self.assertGreaterEqual(p["payload"].count(":"), 5)

    def test_index_referenced(self):
        self.assertIn("graphql_mutation_aliasing_account_recovery_dos_2026", _index())


class W28cPickToolRoutingTest(unittest.IsolatedAsyncioTestCase):
    """W28-c — verb-led queries for the new vuln vocabulary must route to
    auto_probe with the right KB category. Existing bare-noun routes
    (sqli / xss / etc) must NOT regress."""

    async def _route(self, q: str) -> str:
        from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl
        return await pick_tool_impl(q)

    async def test_marimo_routes_to_websocket(self):
        out = await self._route("marimo rce probe check")
        self.assertIn("auto_probe", out)
        self.assertIn("websocket", out)

    async def test_magento_mirasvit_routes_to_deserialization(self):
        out = await self._route("magento mirasvit deserialization")
        self.assertIn("auto_probe", out)
        self.assertIn("deserialization", out)

    async def test_vite_devserver_routes_to_source_exposure(self):
        out = await self._route("vite dev path traversal")
        self.assertIn("auto_probe", out)
        self.assertIn("source_code_exposure", out)

    async def test_nextjs_ws_ssrf_routes_to_edge_ssrf(self):
        out = await self._route("nextjs websocket ssrf canary")
        self.assertIn("auto_probe", out)
        self.assertIn("edge_worker_ssrf", out)

    async def test_illegal_utf8_routes_to_ai_pi(self):
        out = await self._route("illegal utf8 jailbreak filter bypass")
        self.assertIn("auto_probe", out)
        self.assertIn("ai_prompt_injection", out)

    async def test_graphql_aliasing_routes_to_graphql(self):
        out = await self._route("graphql mutation aliasing rate limit bypass")
        self.assertIn("auto_probe", out)
        self.assertIn("graphql", out)

    async def test_bare_sqli_still_routes_to_auto_probe(self):
        """Sanity: existing bare-noun route preserved."""
        out = await self._route("scan target for sqli")
        self.assertIn("auto_probe", out)

    async def test_send_to_repeater_still_routes(self):
        out = await self._route("send to repeater")
        self.assertIn("send_to_repeater", out)


class W28bKbOrgComplianceTest(unittest.TestCase):
    """Per KB-org rule: no new dated/v2 sibling files for any of the 6 additions."""

    def test_no_dated_sibling_files(self):
        forbidden = [
            "nextjs_websocket_ssrf.json",
            "magento_mirasvit.json",
            "marimo.json",
            "vite_devserver.json",
            "illegal_utf8.json",
            "graphql_mutation_aliasing.json",
            "graphql_2026.json",
            "websocket_2026.json",
        ]
        for name in forbidden:
            self.assertFalse(
                (_KB / name).exists(),
                f"KB-org violation: dated/v2 sibling {name} must not exist"
            )


if __name__ == "__main__":
    unittest.main()
