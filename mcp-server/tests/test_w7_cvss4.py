"""Tests for CVSS 4.0 vector + band module (W7, T6)."""

from __future__ import annotations

import unittest

from praetor.tools.advisor import _cvss4


class CVSS4Test(unittest.TestCase):

    def test_build_sqli_default(self):
        v = _cvss4.build_vector("sqli")
        self.assertTrue(v.startswith("CVSS:4.0/"))
        self.assertIn("AV:N", v)
        self.assertIn("VC:H", v)
        # Real FIRST.org CVSS 4.0: unauth SQLi (VC:H/VI:H) is 9.3 -> Critical
        # (the prior MacroVector approximation under-rated it as High).
        self.assertEqual(_cvss4.severity_band(v), "Critical")

    def test_build_rce_critical(self):
        v = _cvss4.build_vector("rce")
        self.assertEqual(_cvss4.severity_band(v), "Critical")

    def test_real_base_score_from_lib(self):
        # Exact FIRST.org reference values, not the MacroVector approximation.
        v = _cvss4.build_vector("sqli")
        self.assertEqual(_cvss4.base_score(v), 9.3)
        self.assertEqual(_cvss4.band_from_score(9.3), "Critical")
        self.assertEqual(_cvss4.band_from_score(0.0), "None")
        self.assertEqual(_cvss4.band_from_score(5.5), "Medium")
        # 3.1 projection also scores via the lib.
        v31 = _cvss4.to_cvss31_vector(_cvss4.parse_vector(v))
        self.assertIsInstance(_cvss4.cvss31_score(v31), float)

    def test_unknown_vuln_falls_back(self):
        v = _cvss4.build_vector("totally_made_up_class")
        parsed = _cvss4.parse_vector(v)
        # Falls back to info_disclosure: VC:L, no VI/VA impact.
        self.assertEqual(parsed["VC"], "L")

    def test_evidence_modifies_metrics(self):
        # sqli defaults PR:N; flipping requires_auth promotes to PR:L.
        v_anon = _cvss4.build_vector("sqli")
        v_auth = _cvss4.build_vector("sqli", evidence={"requires_auth": True})
        self.assertIn("PR:N", v_anon)
        self.assertIn("PR:L", v_auth)

        v_admin = _cvss4.build_vector("sqli", evidence={"requires_admin": True})
        self.assertIn("PR:H", v_admin)

        v_oob = _cvss4.build_vector("ssrf", evidence={"oob_only": True})
        parsed = _cvss4.parse_vector(v_oob)
        self.assertEqual(parsed["AT"], "P")
        self.assertEqual(parsed["AC"], "H")

    def test_env_overrides_filtered(self):
        v = _cvss4.build_vector("xss", env={"E": "A", "CR": "H", "INVALID": "X", "AV": "BAD"})
        parsed = _cvss4.parse_vector(v)
        self.assertEqual(parsed.get("E"), "A")
        self.assertEqual(parsed.get("CR"), "H")
        self.assertNotIn("INVALID", v)

    def test_parse_rejects_bad_prefix(self):
        with self.assertRaises(ValueError):
            _cvss4.parse_vector("CVSS:3.1/AV:N/AC:L")

    def test_parse_rejects_unknown_metric(self):
        with self.assertRaises(ValueError):
            _cvss4.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/FOO:X")

    def test_parse_rejects_invalid_value(self):
        with self.assertRaises(ValueError):
            _cvss4.parse_vector("CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

    def test_macrovector_5digit(self):
        p = _cvss4.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        mv = _cvss4.macrovector(p)
        self.assertEqual(len(mv), 5)
        self.assertTrue(all(c.isdigit() for c in mv))

    def test_cvss31_projection(self):
        p = _cvss4.parse_vector(_cvss4.build_vector("rce"))
        v31 = _cvss4.to_cvss31_vector(p)
        self.assertTrue(v31.startswith("CVSS:3.1/"))
        self.assertIn("AV:N", v31)
        self.assertIn("C:H", v31)


class CvssDeterminismTest(unittest.TestCase):
    """Same class + same shape flags -> the SAME vector every run (no per-run drift)."""

    def test_build_vector_is_deterministic(self):
        from praetor.tools.advisor._cvss4 import build_vector
        for vt in ("sqli", "xss", "ssrf", "idor", "csrf"):
            vecs = {build_vector(vt, {"requires_auth": True}) for _ in range(10)}
            self.assertEqual(len(vecs), 1, f"{vt} produced {len(vecs)} distinct vectors")

    def test_shape_flags_are_the_only_variance(self):
        from praetor.tools.advisor._cvss4 import build_vector
        # different flags -> may differ; identical flags -> identical, always.
        a = build_vector("sqli", {"requires_auth": True, "requires_interaction": True})
        b = build_vector("sqli", {"requires_auth": True, "requires_interaction": True})
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
