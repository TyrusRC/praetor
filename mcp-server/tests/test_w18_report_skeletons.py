"""W18 — per-vuln-class report skeletons appended to report-templates.md."""

from __future__ import annotations

import unittest
from pathlib import Path


def _read_skill(name: str) -> str:
    p = Path(f"../.claude/skills/{name}")
    if not p.exists():
        p = Path(f".claude/skills/{name}")
    return p.read_text(encoding="utf-8") if p.exists() else ""


class PerClassReportSkeletonTest(unittest.TestCase):

    def setUp(self):
        self.content = _read_skill("report-templates.md")

    def test_per_vuln_class_section_present(self):
        self.assertIn("Per-vuln-class report skeletons", self.content,
                      "report-templates.md missing W18 per-vuln-class section")

    def test_ssrf_skeleton_present(self):
        for marker in ("vuln_type: ssrf", "CWE-918",
                       "AccessKeyId / instance-id", "nip.io"):
            self.assertIn(marker, self.content, f"SSRF skeleton missing: {marker}")

    def test_idor_skeleton_present(self):
        for marker in ("vuln_type: idor", "CWE-639", "API1:2023",
                       "cross_principal_verified", "id_shape"):
            self.assertIn(marker, self.content, f"IDOR skeleton missing: {marker}")

    def test_jwt_skeleton_present(self):
        for marker in ("vuln_type: jwt", "CWE-345", "alg confusion",
                       "kid traversal", "forge_jwt"):
            self.assertIn(marker, self.content, f"JWT skeleton missing: {marker}")

    def test_oauth_skeleton_present(self):
        for marker in ("vuln_type: oauth", "CWE-601",
                       "redirect_uri", "PKCE",
                       "mix-up", "JWKS"):
            self.assertIn(marker, self.content, f"OAuth skeleton missing: {marker}")

    def test_smuggling_skeleton_present(self):
        for marker in ("vuln_type: request_smuggling", "CWE-444",
                       "CL.TE", "Kettle 2025", "CVE-2025-32094"):
            self.assertIn(marker, self.content, f"smuggling skeleton missing: {marker}")

    def test_pp_skeleton_present(self):
        for marker in ("vuln_type: <cspp | sspp>", "CWE-1321",
                       "DOMPurify", "isAdmin", "exec_argv",
                       "CVE-2024-21509"):
            self.assertIn(marker, self.content, f"PP skeleton missing: {marker}")

    def test_quick_pick_table_present(self):
        self.assertIn("Quick-pick reference", self.content,
                      "missing Quick-pick reference table")
        for class_name in ("SSRF", "IDOR / BOLA", "JWT", "OAuth / OIDC",
                           "Request smuggling", "Prototype pollution"):
            self.assertIn(class_name, self.content,
                          f"quick-pick row missing for: {class_name}")


if __name__ == "__main__":
    unittest.main()
