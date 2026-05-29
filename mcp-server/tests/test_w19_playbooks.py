"""W19 — 3 more deep-dive playbooks (deserialization, SAML XSW, GraphQL)
+ per-class PoC verify hints."""

from __future__ import annotations

import unittest
from pathlib import Path


def _read_skill(name: str) -> str:
    p = Path(f"../.claude/skills/{name}")
    if not p.exists():
        p = Path(f".claude/skills/{name}")
    return p.read_text(encoding="utf-8") if p.exists() else ""


class DeserializationPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-deserialization.md")
        self.assertGreater(len(content), 1500)

    def test_all_formats_covered(self):
        content = _read_skill("playbook-deserialization.md")
        for fmt in ("Java serialized", "BinaryFormatter", "ViewState",
                    "PHP serialize", "pickle", "PyYAML", "Ruby Marshal",
                    "node-serialize"):
            self.assertIn(fmt, content, f"deserialization format missing: {fmt}")

    def test_ysoserial_chains_present(self):
        content = _read_skill("playbook-deserialization.md")
        for chain in ("CommonsCollections1", "Spring1", "BeanShell1",
                      "Hibernate1", "URLDNS", "JRMP"):
            self.assertIn(chain, content, f"ysoserial chain missing: {chain}")

    def test_references_tools(self):
        content = _read_skill("playbook-deserialization.md")
        for tool in ("generate_deserialization_gadget", "confirm_rce"):
            self.assertIn(tool, content, f"deserialization tool ref missing: {tool}")


class SAMLXSWPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-saml-xsw.md")
        self.assertGreater(len(content), 1500)

    def test_eight_variants_documented(self):
        content = _read_skill("playbook-saml-xsw.md")
        for variant in ("XSW1", "XSW2", "XSW3", "XSW4",
                        "XSW5", "XSW6", "XSW7", "XSW8"):
            self.assertIn(variant, content, f"XSW variant missing: {variant}")

    def test_somorovsky_referenced(self):
        content = _read_skill("playbook-saml-xsw.md")
        self.assertIn("Somorovsky", content)

    def test_processor_examples_present(self):
        content = _read_skill("playbook-saml-xsw.md")
        for processor in ("OpenSAML", "SimpleSAMLphp"):
            self.assertIn(processor, content,
                          f"SAML processor example missing: {processor}")


class GraphQLDeepPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-graphql-deep.md")
        self.assertGreater(len(content), 1500)

    def test_engine_inventory(self):
        content = _read_skill("playbook-graphql-deep.md")
        for engine in ("Apollo", "graphql-js", "Hasura",
                       "PostGraphile", "Mercurius", "AppSync", "Dgraph",
                       "Strawberry"):
            self.assertIn(engine, content,
                          f"GraphQL engine missing: {engine}")

    def test_attack_classes_present(self):
        content = _read_skill("playbook-graphql-deep.md")
        for attack in ("Introspection", "Field suggestion",
                       "Batching", "Alias-based DoS",
                       "Depth limits", "Persisted query bypass",
                       "Subscription protocol drift",
                       "Hasura admin secret bypass",
                       "PostGraphile RLS bypass",
                       "Federation `_entities`"):
            self.assertIn(attack, content,
                          f"GraphQL attack missing: {attack}")

    def test_w18_subscription_drift_referenced(self):
        content = _read_skill("playbook-graphql-deep.md")
        self.assertIn("subscription_protocol_drift_2025", content)
        self.assertIn("subscriptions-transport-ws", content)

    def test_references_tools(self):
        content = _read_skill("playbook-graphql-deep.md")
        for tool in ("test_graphql", "test_websocket"):
            self.assertIn(tool, content, f"GraphQL tool ref missing: {tool}")


class PocVerifyClassTemplatesTest(unittest.TestCase):
    """W19-T5 — _VERIFY_HINTS extended with class-specific markers."""

    def test_new_class_keys_present(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _VERIFY_HINTS
        for cls in ("ssrf_cloud_metadata", "ssrf_internal_service",
                    "idor", "bola", "jwt", "oauth",
                    "request_smuggling", "sspp", "cspp",
                    "prototype_pollution", "deserialization",
                    "saml_xsw", "graphql"):
            self.assertIn(cls, _VERIFY_HINTS,
                          f"W19 verify hint class missing: {cls}")

    def test_ssrf_cloud_metadata_markers(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _VERIFY_HINTS
        markers = _VERIFY_HINTS["ssrf_cloud_metadata"]
        for required in ("AccessKeyId", "ami-id", "computeMetadata"):
            self.assertIn(required, markers,
                          f"SSRF cloud markers missing: {required}")

    def test_ssrf_internal_service_markers(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _VERIFY_HINTS
        markers = _VERIFY_HINTS["ssrf_internal_service"]
        # At least one internal-service banner.
        self.assertTrue(any("SSH" in m or "OpenSSH" in m for m in markers),
                        "SSRF internal markers should include SSH banner")
        self.assertTrue(any("-ERR" in m or "NOAUTH" in m for m in markers),
                        "SSRF internal markers should include Redis banner")

    def test_sspp_admin_marker(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _VERIFY_HINTS
        # SSPP markers should look for admin-flag responses
        sspp = " ".join(_VERIFY_HINTS["sspp"])
        self.assertTrue("admin" in sspp.lower(),
                        "SSPP markers should look for admin-flag")


if __name__ == "__main__":
    unittest.main()
