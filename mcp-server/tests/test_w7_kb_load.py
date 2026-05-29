"""Tests for the 5 W7 KB additions (T5) — load + schema sanity."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY


_W7_ACTIVE = ["etag_xsleak", "xsleak_redirect", "parser_differential"]
_W7_REFERENCE = ["http2_connect_portscan", "soapwn"]
_W7_ALL = _W7_ACTIVE + _W7_REFERENCE


class W7KBLoadTest(unittest.TestCase):

    def test_all_files_exist_and_parse(self):
        for name in _W7_ALL:
            path = Path(KNOWLEDGE_DIR) / f"{name}.json"
            self.assertTrue(path.exists(), f"missing {name}.json")
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data.get("category"), name, f"{name}: category mismatch")
            self.assertIn("contexts", data, f"{name}: no contexts")
            self.assertGreater(len(data["contexts"]), 0, f"{name}: empty contexts")

    def test_each_context_has_probes(self):
        for name in _W7_ALL:
            data = json.loads((Path(KNOWLEDGE_DIR) / f"{name}.json").read_text())
            for ctx_name, ctx in data["contexts"].items():
                probes = ctx.get("probes", [])
                self.assertGreater(len(probes), 0, f"{name}/{ctx_name}: no probes")
                for probe in probes:
                    self.assertIn("matchers", probe, f"{name}/{ctx_name}: probe missing matchers")
                    self.assertIn("severity", probe, f"{name}/{ctx_name}: probe missing severity")
                    self.assertIn(probe["severity"], ["info", "low", "medium", "high", "critical"])

    def test_reference_only_set_correct(self):
        for name in _W7_REFERENCE:
            self.assertIn(name, _REFERENCE_ONLY, f"{name} should be in _REFERENCE_ONLY")
        for name in _W7_ACTIVE:
            self.assertNotIn(name, _REFERENCE_ONLY, f"{name} should NOT be in _REFERENCE_ONLY")


if __name__ == "__main__":
    unittest.main()
