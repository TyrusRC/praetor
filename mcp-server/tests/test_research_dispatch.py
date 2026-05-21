"""Dispatch + shim tests for the research/ package split.

Confirms every previously-importable symbol is still reachable via the
old `burpsuite_mcp.tools.research` path and that register() wires a
single MCP tool.
"""

from __future__ import annotations

import unittest


class TestResearchShim(unittest.TestCase):
    def test_all_symbols_importable_via_old_path(self):
        from burpsuite_mcp.tools.research import (
            _METHODOLOGY_LINKS,
            _VECTOR_KB,
            _attackerkb_search,
            _exploitdb_search,
            _github_advisory_search,
            _github_code_search,
            _osv_search,
            _snyk_db_search,
            register,
        )
        for sym in (
            _exploitdb_search,
            _osv_search,
            _github_advisory_search,
            _snyk_db_search,
            _attackerkb_search,
            _github_code_search,
        ):
            self.assertTrue(callable(sym))
        self.assertTrue(callable(register))
        self.assertIsInstance(_VECTOR_KB, dict)
        self.assertIsInstance(_METHODOLOGY_LINKS, dict)
        self.assertIn("sqli", _VECTOR_KB)
        self.assertIn("sqli", _METHODOLOGY_LINKS)

    def test_backend_submodules_importable_directly(self):
        from burpsuite_mcp.tools.research.attackerkb import _attackerkb_search
        from burpsuite_mcp.tools.research.exploitdb import _exploitdb_search
        from burpsuite_mcp.tools.research.github_advisory import (
            _github_advisory_search,
        )
        from burpsuite_mcp.tools.research.github_code import _github_code_search
        from burpsuite_mcp.tools.research.osv import _osv_search
        from burpsuite_mcp.tools.research.snyk import _snyk_db_search

        self.assertIn("exploit-db.com", _exploitdb_search("nginx"))
        self.assertIn("osv.dev", _osv_search("nginx"))
        self.assertIn("github.com/advisories", _github_advisory_search("nginx"))
        self.assertIn("snyk.io", _snyk_db_search("nginx"))
        self.assertIn("attackerkb.com", _attackerkb_search("nginx"))
        self.assertIn("github.com/search", _github_code_search("nginx"))

    def test_register_adds_research_attack_vector_tool(self):
        tools: list[str] = []

        class StubMcp:
            def tool(self, *args, **kwargs):
                def decorator(fn):
                    tools.append(fn.__name__)
                    return fn
                return decorator

        from burpsuite_mcp.tools.research import register

        register(StubMcp())
        self.assertEqual(tools, ["research_attack_vector"])


if __name__ == "__main__":
    unittest.main()
