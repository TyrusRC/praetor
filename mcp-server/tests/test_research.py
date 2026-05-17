"""Calibration tests for research_attack_vector.

The tool is pure-Python URL-builder + KB lookup — no network calls — so
we can exercise it directly without a Burp backend.
"""

from __future__ import annotations

import asyncio
import unittest

from burpsuite_mcp.tools.research import (
    _VECTOR_KB,
    _METHODOLOGY_LINKS,
    _exploitdb_search,
    _osv_search,
    _github_advisory_search,
    _snyk_db_search,
    _attackerkb_search,
    _github_code_search,
    register,
)
from mcp.server.fastmcp import FastMCP


class VectorKBInvariants(unittest.TestCase):
    EXPECTED_KEYS = {"deep_dive", "obscure", "chain"}

    def test_every_class_has_three_required_sections(self):
        for cls, entry in _VECTOR_KB.items():
            self.assertEqual(set(entry.keys()), self.EXPECTED_KEYS,
                             f"{cls}: expected sections {self.EXPECTED_KEYS}, got {set(entry.keys())}")

    def test_every_section_nonempty(self):
        for cls, entry in _VECTOR_KB.items():
            for sect in self.EXPECTED_KEYS:
                self.assertGreater(len(entry[sect]), 0,
                                   f"{cls}.{sect} is empty")
                for item in entry[sect]:
                    self.assertGreater(len(item), 20,
                                       f"{cls}.{sect} item too short: {item!r}")

    def test_critical_classes_present(self):
        REQUIRED = {"sqli", "xss", "ssrf", "ssti", "idor", "rce", "csrf",
                    "xxe", "auth_bypass"}
        missing = REQUIRED - set(_VECTOR_KB)
        self.assertFalse(missing, f"missing critical KB entries: {missing}")

    def test_no_section_uses_destructive_payloads(self):
        FORBIDDEN = ("DROP TABLE ", "rm -rf /", "shutdown now",
                     "DELETE FROM users")
        for cls, entry in _VECTOR_KB.items():
            for sect in self.EXPECTED_KEYS:
                for item in entry[sect]:
                    for bad in FORBIDDEN:
                        self.assertNotIn(bad, item,
                                         f"{cls}.{sect} contains destructive token: {bad!r}")


class MethodologyLinks(unittest.TestCase):
    REQUIRED_KEYS = {"portswigger", "hacktricks", "patt", "owasp"}

    def test_every_kb_class_has_methodology_entry(self):
        # The methodology table must mirror the KB so every reported class
        # gets at least a deep-link.
        kb_classes = set(_VECTOR_KB.keys())
        meth_classes = set(_METHODOLOGY_LINKS.keys())
        missing = kb_classes - meth_classes
        self.assertFalse(missing,
                         f"KB classes missing methodology deep-links: {missing}")

    def test_entries_have_four_required_keys(self):
        for cls, entry in _METHODOLOGY_LINKS.items():
            self.assertEqual(set(entry.keys()), self.REQUIRED_KEYS,
                             f"{cls}: missing keys {self.REQUIRED_KEYS - set(entry.keys())}")

    def test_portswigger_hacktricks_patt_all_https(self):
        # PortSwigger / HackTricks / PAYLOADs are mandatory — they must be
        # full HTTPS URLs (verified static HTML). OWASP WSTG may be empty.
        for cls, entry in _METHODOLOGY_LINKS.items():
            for k in ("portswigger", "hacktricks", "patt"):
                url = entry.get(k, "")
                self.assertTrue(url.startswith("https://"),
                                f"{cls}.{k} not a full URL: {url!r}")

    def test_portswigger_academy_domain(self):
        # PortSwigger Academy URLs must point at the Academy path.
        for cls, entry in _METHODOLOGY_LINKS.items():
            self.assertIn("portswigger.net/web-security", entry["portswigger"],
                          f"{cls}: PortSwigger URL not Academy-shaped")

    def test_hacktricks_book_domain(self):
        for cls, entry in _METHODOLOGY_LINKS.items():
            self.assertIn("book.hacktricks.xyz", entry["hacktricks"],
                          f"{cls}: HackTricks URL not book.hacktricks.xyz")

    def test_patt_is_swisskyrepo_url(self):
        for cls, entry in _METHODOLOGY_LINKS.items():
            self.assertIn("swisskyrepo/PayloadsAllTheThings", entry["patt"],
                          f"{cls}: PAYLOADs URL malformed")


class URLBuilders(unittest.TestCase):
    """Each builder is a verified server-rendered endpoint."""

    def test_exploitdb_search(self):
        url = _exploitdb_search("ssrf 2024")
        self.assertTrue(url.startswith("https://www.exploit-db.com/search?text="))
        self.assertIn("ssrf+2024", url)

    def test_osv_search(self):
        url = _osv_search("django")
        self.assertEqual(url, "https://osv.dev/list?q=django")

    def test_github_advisory_search(self):
        url = _github_advisory_search("CVE-2024-1234")
        self.assertTrue(url.startswith("https://github.com/advisories?query="))
        self.assertIn("CVE-2024-1234", url)

    def test_snyk_db_search(self):
        url = _snyk_db_search("axios")
        self.assertTrue(url.startswith("https://security.snyk.io/vuln/?search="))
        self.assertIn("axios", url)

    def test_attackerkb_search(self):
        url = _attackerkb_search("Log4Shell")
        self.assertTrue(url.startswith("https://attackerkb.com/search?q="))
        self.assertIn("Log4Shell", url)

    def test_github_code_search(self):
        url = _github_code_search("findByPk req.params.id language:javascript")
        self.assertTrue(url.startswith("https://github.com/search?q="))
        self.assertIn("type=code", url)


class ToolEndToEnd(unittest.TestCase):
    """Drive the actual MCP tool function end-to-end (no backend)."""

    def setUp(self):
        self.mcp = FastMCP("test")
        register(self.mcp)
        self.tool = self.mcp._tool_manager._tools["research_attack_vector"]

    def _run(self, **kwargs):
        return asyncio.run(self.tool.fn(**kwargs))

    def test_known_class_produces_all_sections(self):
        out = self._run(vuln_type="ssrf", tech_stack="node,express",
                        finding_summary="image-proxy fetches arbitrary URLs",
                        endpoint="/api/preview",
                        target_domain="example.com")
        for section in ("DEEP-DIVE QUESTIONS",
                        "OBSCURE VECTORS",
                        "CHAIN HYPOTHESES",
                        "METHODOLOGY DEEP-LINKS",
                        "SUGGESTED WEB SEARCHES",
                        "ADVISORY DATABASES",
                        "GITHUB CODE SEARCH",
                        "COMPLEMENTARY MCP CALLS",
                        "TRIAGE PROTOCOL"):
            self.assertIn(section, out, f"missing section: {section}")

    def test_methodology_section_contains_all_four_sources(self):
        out = self._run(vuln_type="sqli")
        self.assertIn("portswigger.net/web-security/sql-injection", out)
        self.assertIn("book.hacktricks.xyz", out)
        self.assertIn("swisskyrepo/PayloadsAllTheThings", out)
        self.assertIn("owasp.org/www-project-web-security-testing-guide", out)

    @staticmethod
    def _section(out: str, header_keyword: str) -> str:
        # Get everything after the header line, up to the next "\n── " boundary.
        after = out.split(header_keyword, 1)[1]
        nxt = after.find("\n── ")
        return after[:nxt] if nxt >= 0 else after

    def test_websearch_section_uses_websearch_not_webfetch(self):
        out = self._run(vuln_type="ssrf",
                        finding_summary="x",
                        target_domain="acme-bb.com")
        websearch_block = self._section(out, "SUGGESTED WEB SEARCHES")
        self.assertIn("WebSearch", websearch_block)
        self.assertIn("site:hackerone.com/reports", websearch_block)
        self.assertIn("acme-bb.com", websearch_block)

    def test_advisory_db_section_has_all_five(self):
        out = self._run(vuln_type="rce", tech_stack="spring-boot")
        adv_block = self._section(out, "ADVISORY DATABASES")
        for db in ("exploit-db.com", "osv.dev", "github.com/advisories",
                   "security.snyk.io", "attackerkb.com"):
            self.assertIn(db, adv_block, f"advisory section missing {db}")

    def test_unknown_class_falls_back_gracefully(self):
        out = self._run(vuln_type="some_novel_class_xyz",
                        finding_summary="weird behavior")
        self.assertIn("No structured KB", out)
        self.assertIn("SUGGESTED WEB SEARCHES", out)
        # METHODOLOGY DEEP-LINKS section is skipped for unknown classes
        self.assertNotIn("METHODOLOGY DEEP-LINKS (some_novel_class_xyz)", out)

    def test_alias_resolution_sqlinjection(self):
        out = self._run(vuln_type="sql_injection")
        self.assertNotIn("No structured KB", out)
        self.assertIn("DEEP-DIVE QUESTIONS (sqli)", out)
        self.assertIn("METHODOLOGY DEEP-LINKS (sqli)", out)

    def test_target_domain_drives_priors_search(self):
        out = self._run(vuln_type="idor",
                        target_domain="acme-bb.com")
        self.assertIn("acme-bb.com hackerone disclosed report", out)
        self.assertIn("priors on this target", out)

    def test_tech_stack_drives_code_search_and_advisory(self):
        out_with = self._run(vuln_type="idor", tech_stack="javascript")
        out_without = self._run(vuln_type="idor")
        self.assertIn("GITHUB CODE SEARCH", out_with)
        self.assertNotIn("GITHUB CODE SEARCH", out_without)
        # Advisory DB section appears in both cases (uses query_base when
        # tech_stack absent) — but tech_stack changes the search keyword.
        self.assertIn("javascript", out_with)


if __name__ == "__main__":
    unittest.main()
