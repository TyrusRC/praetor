"""W20 — 3 more deep-dive playbooks (WebSocket attacks, Web Cache Deception,
Server Action / RSC)."""

from __future__ import annotations

import unittest
from pathlib import Path


def _read_skill(name: str) -> str:
    p = Path(f"../.claude/skills/{name}")
    if not p.exists():
        p = Path(f".claude/skills/{name}")
    return p.read_text(encoding="utf-8") if p.exists() else ""


class WebSocketAttacksPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-websocket-attacks.md")
        self.assertGreater(len(content), 1500)

    def test_attack_classes_covered(self):
        content = _read_skill("playbook-websocket-attacks.md")
        for attack in ("CSWSH", "Cross-Site WebSocket Hijacking",
                       "Missing Origin", "Wildcard Origin",
                       "Token in URL", "No auth required",
                       "Subprotocol negotiation", "Per-message",
                       "Subscription protocol drift", "Binary frame smuggling",
                       "Message replay", "WS through OAuth"):
            self.assertIn(attack, content, f"WS attack missing: {attack}")

    def test_references_tools(self):
        content = _read_skill("playbook-websocket-attacks.md")
        for tool in ("test_websocket", "websocket_send_message",
                     "get_websocket_history"):
            self.assertIn(tool, content, f"WS tool ref missing: {tool}")

    def test_cross_refs_w18(self):
        content = _read_skill("playbook-websocket-attacks.md")
        self.assertIn("subscription_protocol_drift_2025", content,
                      "WS playbook should cross-ref W18 subscription drift")


class CacheDeceptionPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-cache-deception.md")
        self.assertGreater(len(content), 1500)

    def test_cdn_specifics_covered(self):
        content = _read_skill("playbook-cache-deception.md")
        for cdn in ("Cloudflare", "Akamai", "Fastly", "Varnish", "CloudFront"):
            self.assertIn(cdn, content, f"CDN missing: {cdn}")

    def test_attack_variants_covered(self):
        content = _read_skill("playbook-cache-deception.md")
        for variant in ("Static-suffix append", "Path traversal",
                        "Parser-differential", "Web Cache Deception 2.0",
                        "Cache-key smuggling", "Cache poisoning vs deception"):
            self.assertIn(variant, content, f"cache attack missing: {variant}")

    def test_w13_w18_cross_refs(self):
        content = _read_skill("playbook-cache-deception.md")
        self.assertIn("static_suffix_cache_poisoning", content)  # W13
        self.assertIn("nextjs_15_cache_key_confusion", content)  # W18

    def test_references_omer_gil_kettle(self):
        content = _read_skill("playbook-cache-deception.md")
        self.assertIn("Omer Gil", content)
        self.assertIn("Kettle", content)


class ServerActionRSCPlaybookTest(unittest.TestCase):

    def test_present_and_substantial(self):
        content = _read_skill("playbook-server-action-rsc.md")
        self.assertGreater(len(content), 1500)

    def test_attack_surface_covered(self):
        content = _read_skill("playbook-server-action-rsc.md")
        for surface in ("Server Action ID", "RSC payload",
                        "Next-Action", "argument tampering",
                        "Streaming injection", "GET coercion"):
            self.assertIn(surface, content, f"surface missing: {surface}")

    def test_cves_referenced(self):
        content = _read_skill("playbook-server-action-rsc.md")
        for cve in ("CVE-2025-55182", "CVE-2025-66478"):
            self.assertIn(cve, content, f"CVE missing: {cve}")

    def test_w18_cross_ref(self):
        content = _read_skill("playbook-server-action-rsc.md")
        self.assertIn("nextjs_15_cache_key_confusion", content,
                      "RSC playbook should cross-ref W18 cache poisoning")

    def test_nextjs_versions_documented(self):
        content = _read_skill("playbook-server-action-rsc.md")
        self.assertIn("Next.js 13", content)
        self.assertIn("Next.js 15", content)


if __name__ == "__main__":
    unittest.main()
