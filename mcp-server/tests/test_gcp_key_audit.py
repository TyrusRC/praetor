"""Exposed Google/Gemini API key validator (Package 4).

Pure-function coverage + one monkeypatched async-tool path. No real network.
Safe-by-design: the tool validates and ESTIMATES impact; it never fires
billable generation (Veo/Imagen/TTS) against the key's account.
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestPure(unittest.TestCase):
    def setUp(self):
        from praetor.tools import gcp_key_audit as g
        self.g = g

    def test_extract_keys(self):
        v = "AIza" + "0123456789abcdefghijklmnopqrstuvwxyz"[:35]
        keys = self.g.extract_google_keys(f"x {v} y {v} zz")
        self.assertEqual(keys, [v])          # de-duplicated
        self.assertTrue(all(k.startswith("AIza") for k in keys))

    def test_redact_shows_shape_only(self):
        r = self.g.redact_key("AIza" + "0123456789abcdefghijklmnopqrstuvwxyz"[:35])
        self.assertTrue(r.startswith("AIza"))
        self.assertIn("…", r)
        self.assertNotIn("0123456789abcdefghij", r)  # body not leaked
        self.assertTrue(r.endswith("wxy"))

    def test_classify_active_lists_models(self):
        body = '{"models":[{"name":"models/gemini-2.5-flash"},{"name":"models/gemini-pro"}]}'
        c = self.g.classify_gemini(200, body)
        self.assertTrue(c["active"])
        self.assertIn("gemini-2.5-flash", c["models"])
        self.assertEqual(c["restriction"], "none")

    def test_classify_403_is_restricted(self):
        c = self.g.classify_gemini(403, '{"error":{"status":"PERMISSION_DENIED"}}')
        self.assertFalse(c["active"])
        self.assertEqual(c["restriction"], "restricted")

    def test_classify_400_invalid_key(self):
        c = self.g.classify_gemini(400, '{"error":{"status":"INVALID_ARGUMENT","message":"API_KEY_INVALID"}}')
        self.assertFalse(c["active"])
        self.assertEqual(c["restriction"], "invalid")

    def test_estimate_impact_names_costly_models(self):
        imp = self.g.estimate_impact(["gemini-2.5-flash", "veo-3.0", "imagen-4.0"])
        joined = " ".join(imp).lower()
        self.assertIn("video", joined)   # veo -> video cost line
        self.assertIn("image", joined)   # imagen -> image cost line


class TestTool(unittest.TestCase):
    def setUp(self):
        from praetor.tools import gcp_key_audit as g
        self.g = g

    def test_tool_redacts_key_and_never_generates(self):
        import asyncio

        calls = []

        async def fake_get(url, headers, timeout):
            calls.append(url)
            return 200, '{"models":[{"name":"models/gemini-2.5-flash"}]}'

        self.g._http_get = fake_get  # monkeypatch network
        from mcp.server.fastmcp import FastMCP

        reg = {}
        mcp = FastMCP("t")
        mcp.tool = lambda: (lambda fn: reg.setdefault(fn.__name__, fn) or fn)
        self.g.register(mcp)

        key = "AIza" + "0123456789abcdefghijklmnopqrstuvwxyz"[:35]
        out = asyncio.run(reg["audit_google_api_key"](key))
        # full key must never appear in output
        self.assertNotIn(key, str(out))
        self.assertTrue(out["active"])
        # only the read-only models endpoint was hit — no generateContent/predict
        self.assertTrue(all("generateContent" not in u and ":predict" not in u for u in calls))


if __name__ == "__main__":
    unittest.main()
