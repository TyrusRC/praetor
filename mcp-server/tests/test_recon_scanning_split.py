"""Smoke + behavior tests for the recon/scanning package split (A2)."""

import unittest


class TestReconScanningShim(unittest.TestCase):
    def test_register_aggregator_callable(self):
        from burpsuite_mcp.tools.recon import scanning
        self.assertTrue(callable(scanning.register))

    def test_seclists_helpers_importable_from_package(self):
        from burpsuite_mcp.tools.recon.scanning import (
            _SECLISTS_CANDIDATES,
            _cache_seclists,
            detect_seclists,
        )
        self.assertTrue(callable(detect_seclists))
        self.assertTrue(callable(_cache_seclists))
        self.assertIsInstance(_SECLISTS_CANDIDATES, list)

    def test_inventory_still_imports_detect_seclists(self):
        # inventory.py uses `from .scanning import detect_seclists`
        from burpsuite_mcp.tools.recon import inventory
        from burpsuite_mcp.tools.recon.scanning import detect_seclists
        # Same callable resolved both ways
        self.assertIs(inventory.detect_seclists, detect_seclists)

    def test_wordlist_still_imports_detect_seclists(self):
        # tools/wordlist.py imports `from burpsuite_mcp.tools.recon.scanning import detect_seclists`
        from burpsuite_mcp.tools import wordlist
        from burpsuite_mcp.tools.recon.scanning import detect_seclists
        self.assertIs(wordlist.detect_seclists, detect_seclists)

    def test_submodules_importable(self):
        from burpsuite_mcp.tools.recon.scanning import (
            archive,
            dirbust,
            dns_intel,
            subdomain,
            vuln_scan,
        )
        for mod in (vuln_scan, dirbust, subdomain, dns_intel, archive):
            self.assertTrue(callable(mod.register), f"{mod.__name__} missing register()")

    def test_register_registers_expected_tools(self):
        tools = []

        class StubMcp:
            def tool(self, *args, **kwargs):
                def decorator(fn):
                    tools.append(fn.__name__)
                    return fn
                return decorator

        from burpsuite_mcp.tools.recon import scanning
        scanning.register(StubMcp())

        expected = {
            "run_nuclei",
            "run_dalfox",
            "run_commix",
            "run_sqlmap",
            "run_wpscan",
            "run_nikto",
            "generate_deserialization_gadget",
            "run_ffuf",
            "run_arjun",
            "run_amass",
            "run_wafw00f",
            "run_httpx",
            "run_gau",
        }
        self.assertEqual(set(tools), expected)
        # No duplicate registrations
        self.assertEqual(len(tools), len(expected))


if __name__ == "__main__":
    unittest.main()
