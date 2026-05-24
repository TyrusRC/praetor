"""Wave 4 — 40x bypass primitives + waf_bypass_40x KB."""

import json
import unittest
from pathlib import Path
from urllib.parse import urlparse

from burpsuite_mcp.tools import waf_bypass


KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


class W4SplitBuildTest(unittest.TestCase):

    def test_split_url_extracts_components(self):
        origin, path, query = waf_bypass._split_url("https://x.test/admin?u=1")
        self.assertEqual(origin, "https://x.test")
        self.assertEqual(path, "/admin")
        self.assertEqual(query, "u=1")

    def test_build_url_preserves_query(self):
        u = waf_bypass._build_url("https://x.test", "/admin/", "u=1")
        parsed = urlparse(u)
        self.assertEqual(parsed.netloc, "x.test")
        self.assertEqual(parsed.path, "/admin/")
        self.assertEqual(parsed.query, "u=1")


class W4BypassClassesPresentTest(unittest.TestCase):

    def test_header_bypasses_include_canonical(self):
        keys = {next(iter(h)) for h in waf_bypass._HEADER_BYPASSES}
        for n in ("X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL",
                  "X-Forwarded-Host", "X-Real-IP", "X-HTTP-Method-Override",
                  "X-Original-Method", "Forwarded"):
            self.assertIn(n, keys)

    def test_path_bypasses_include_canonical(self):
        patterns = waf_bypass._PATH_BYPASSES
        for p in ("{path}/", "{path}/.", "{path}/..;/", "{path};/", "//{path}"):
            self.assertIn(p, patterns)

    def test_method_bypasses_cover_uncommon_verbs(self):
        for m in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"):
            self.assertIn(m, waf_bypass._METHOD_BYPASSES)


class W4KbWafBypassTest(unittest.TestCase):

    def test_kb_loads_and_has_three_contexts(self):
        d = json.loads((KB / "waf_bypass_40x.json").read_text())
        self.assertEqual(d["category"], "waf_bypass_40x")
        for k in ("header_origin_spoof", "path_normalisation_tricks", "method_override"):
            self.assertIn(k, d["contexts"])

    def test_kb_probes_have_matchers(self):
        d = json.loads((KB / "waf_bypass_40x.json").read_text())
        for name, ctx in d["contexts"].items():
            self.assertTrue(ctx.get("probes"), name)
            for p in ctx["probes"]:
                self.assertTrue(p.get("matchers"), name)


if __name__ == "__main__":
    unittest.main()
