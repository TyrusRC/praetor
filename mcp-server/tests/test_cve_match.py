"""Smoke + match-logic tests for the cve/ package shim."""

import unittest


class TestCveShim(unittest.TestCase):
    def test_all_symbols_importable_via_old_path(self):
        from burpsuite_mcp.tools.cve import (
            KNOWLEDGE_DIR,
            _BROWSER_UA,
            _NVD_API_URL,
            _SHODAN_CPE_URL,
            _SHODAN_CPES_URL,
            _SHODAN_CVE_URL,
            _SHODAN_CVES_URL,
            _VERSION_RE,
            _extract_version,
            _load_tech_vulns,
            _match_tech_to_vulns,
            _nvd_lookup,
            _shodan_cpe_dict,
            _shodan_cpe_lookup,
            _shodan_cve_lookup,
            _shodan_cves_query,
            _version_in_range,
            _version_tuple,
            register,
        )
        for sym in (
            _load_tech_vulns, _extract_version, _version_tuple,
            _version_in_range, _match_tech_to_vulns,
            _shodan_cve_lookup, _shodan_cves_query, _shodan_cpe_lookup,
            _shodan_cpe_dict, _nvd_lookup, register,
        ):
            self.assertTrue(callable(sym))
        self.assertIsInstance(_BROWSER_UA, str)
        self.assertTrue(_NVD_API_URL.startswith("https://"))
        self.assertEqual(_SHODAN_CPE_URL, _SHODAN_CVES_URL)
        self.assertTrue(str(KNOWLEDGE_DIR).endswith("knowledge"))
        self.assertIsNotNone(_VERSION_RE.search("Apache/2.4.50"))


class TestCveMatchLogic(unittest.TestCase):
    def test_extract_version_apache(self):
        from burpsuite_mcp.tools.cve import _extract_version
        self.assertEqual(_extract_version("Apache/2.4.50"), "2.4.50")
        self.assertEqual(_extract_version("PHP 8.1.2"), "8.1.2")
        self.assertEqual(_extract_version("nginx"), "")

    def test_version_tuple_basic(self):
        from burpsuite_mcp.tools.cve import _version_tuple
        self.assertEqual(_version_tuple("2.4.50"), (2, 4, 50))
        self.assertEqual(_version_tuple("8.1"), (8, 1))

    def test_version_in_range_any(self):
        from burpsuite_mcp.tools.cve import _version_in_range
        self.assertTrue(_version_in_range("anything", "any"))
        self.assertTrue(_version_in_range("", "any"))

    def test_version_in_range_dashed(self):
        from burpsuite_mcp.tools.cve import _version_in_range
        self.assertTrue(_version_in_range("2.4.50", "2.4.0-2.4.51"))
        self.assertFalse(_version_in_range("2.5.0", "2.4.0-2.4.51"))
        self.assertTrue(_version_in_range("2.4.0", "2.4.0-2.4.51"))
        self.assertTrue(_version_in_range("2.4.51", "2.4.0-2.4.51"))

    def test_version_in_range_prefix(self):
        from burpsuite_mcp.tools.cve import _version_in_range
        # Exact-segment prefix match: '8.1' matches '8.1' and '8.1.3'
        self.assertTrue(_version_in_range("8.1", "8.1"))
        self.assertTrue(_version_in_range("8.1.3", "8.1"))
        # But NOT '8.10' (regression guard from bidirectional prefix trap)
        self.assertFalse(_version_in_range("8.10", "8.1"))
        # Empty version against non-'any' range → False
        self.assertFalse(_version_in_range("", "2.4.0"))

    def test_match_tech_to_vulns_empty(self):
        from burpsuite_mcp.tools.cve import _match_tech_to_vulns
        self.assertEqual(_match_tech_to_vulns([], {}), [])
        self.assertEqual(_match_tech_to_vulns(["nginx/1.0"], {}), [])

    def test_match_tech_to_vulns_basic(self):
        from burpsuite_mcp.tools.cve import _match_tech_to_vulns
        tech_vulns = {
            "technologies": {
                "apache": {
                    "versions": {
                        "2.4.49": {
                            "cves": ["CVE-2021-41773"],
                            "severity": "high",
                            "tests": ["LFI via path traversal"],
                        },
                    },
                    "common_issues": ["Default server banner exposure"],
                    "default_paths": ["/server-status"],
                },
            },
        }
        matches = _match_tech_to_vulns(["Apache/2.4.49"], tech_vulns)
        self.assertTrue(any(m["cve"] == "CVE-2021-41773" for m in matches))
        self.assertTrue(any(m["severity"] == "HIGH" for m in matches))
        self.assertTrue(any(m["severity"] == "LOW" for m in matches))  # default_paths
        self.assertTrue(any(m["severity"] == "MEDIUM" for m in matches))  # common_issues


if __name__ == "__main__":
    unittest.main()
