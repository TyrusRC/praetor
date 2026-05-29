"""W16 — 3 new deep-dive playbook skills."""

from __future__ import annotations

import unittest
from pathlib import Path


def _read_skill(name: str) -> str:
    p = Path(f"../.claude/skills/{name}")
    if not p.exists():
        p = Path(f".claude/skills/{name}")
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")


class SSRFPlaybookTest(unittest.TestCase):

    def test_ssrf_playbook_present(self):
        content = _read_skill("playbook-ssrf-deep-dive.md")
        self.assertGreater(len(content), 1000, "SSRF playbook missing or too small")

    def test_ssrf_references_real_tools(self):
        content = _read_skill("playbook-ssrf-deep-dive.md")
        for marker in ("test_ssrf", "test_cloud_metadata",
                       "generate_collaborator_payload",
                       "edge_worker_ssrf", "ssrf_protocol", "Rule 9a"):
            self.assertIn(marker, content,
                          f"SSRF playbook missing reference: {marker}")

    def test_ssrf_classification_matrix_present(self):
        content = _read_skill("playbook-ssrf-deep-dive.md")
        for class_name in ("Cloud metadata SSRF", "Blind SSRF",
                           "DNS-rebind SSRF", "Edge-worker SSRF",
                           "Protocol-smuggling SSRF"):
            self.assertIn(class_name, content,
                          f"SSRF playbook missing class: {class_name}")


class IDORBOLAPlaybookTest(unittest.TestCase):

    def test_idor_playbook_present(self):
        content = _read_skill("playbook-idor-bola.md")
        self.assertGreater(len(content), 1000, "IDOR/BOLA playbook missing or too small")

    def test_idor_references_real_tools(self):
        content = _read_skill("playbook-idor-bola.md")
        for marker in ("harvest_identifiers", "probe_id_monotonic",
                       "probe_cross_transport_idor", "test_auth_matrix",
                       "compare_auth_states"):
            self.assertIn(marker, content,
                          f"IDOR playbook missing tool reference: {marker}")

    def test_id_shape_inventory_present(self):
        content = _read_skill("playbook-idor-bola.md")
        for shape in ("UUIDv1", "ULID", "Snowflake", "UUIDv4"):
            self.assertIn(shape, content, f"IDOR playbook missing shape: {shape}")


class JWTPlaybookTest(unittest.TestCase):

    def test_jwt_playbook_present(self):
        content = _read_skill("playbook-jwt-deep-dive.md")
        self.assertGreater(len(content), 1000, "JWT playbook missing or too small")

    def test_jwt_references_real_tools(self):
        content = _read_skill("playbook-jwt-deep-dive.md")
        for marker in ("test_jwt", "forge_jwt", "crack_jwt_secret",
                       "concurrent_requests"):
            self.assertIn(marker, content,
                          f"JWT playbook missing tool reference: {marker}")

    def test_jwt_attack_classes_present(self):
        content = _read_skill("playbook-jwt-deep-dive.md")
        for attack in ("alg:none", "alg confusion (RS→HS)",
                       "jku", "x5u", "kid traversal",
                       "LSR", "cty"):
            self.assertIn(attack, content,
                          f"JWT playbook missing attack: {attack}")


class W16PlaybookRouterIntegrationTest(unittest.TestCase):
    """The 3 W16 playbooks should be discoverable via the playbook-router pattern.

    playbook-router.md routes operator queries to specific playbooks. The W16
    additions should be reachable as topics.
    """

    def test_router_exists(self):
        content = _read_skill("playbook-router.md")
        self.assertGreater(len(content), 100, "playbook-router.md missing")


if __name__ == "__main__":
    unittest.main()
