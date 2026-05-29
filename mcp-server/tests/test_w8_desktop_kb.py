"""Tests for W8 desktop_electron KB + ref-only status."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY


class DesktopElectronKBTest(unittest.TestCase):

    def setUp(self):
        path = Path(KNOWLEDGE_DIR) / "desktop_electron.json"
        self.assertTrue(path.exists(), "desktop_electron.json missing")
        self.data = json.loads(path.read_text(encoding="utf-8"))

    def test_category_metadata(self):
        self.assertEqual(self.data.get("category"), "desktop_electron")
        self.assertIn("Electron", self.data.get("description", ""))

    def test_listed_as_reference_only(self):
        self.assertIn("desktop_electron", _REFERENCE_ONLY)

    def test_static_contexts_have_detect_field(self):
        """Ref-only static contexts must publish a `detect` instruction so
        desktop-agent has a runnable command."""
        for name, ctx in self.data["contexts"].items():
            if not ctx.get("reference_only"):
                continue
            self.assertIn("detect", ctx, f"{name}: missing `detect` field")
            self.assertIn("severity_hint", ctx, f"{name}: missing severity_hint")

    def test_autoupdate_context_is_active(self):
        """The HTTP-bearing autoupdate context should have real matchers."""
        ctx = self.data["contexts"].get("autoupdate_http_mitm")
        self.assertIsNotNone(ctx)
        self.assertNotIn("reference_only", ctx)
        self.assertIn("matchers", ctx)
        self.assertGreater(len(ctx["matchers"]), 0)

    def test_required_cves_documented(self):
        ctx = self.data["contexts"].get("electron_fuse_runasnode_enabled")
        self.assertEqual(ctx.get("cve"), "CVE-2024-23739")
        ctx2 = self.data["contexts"].get("videoframe_contextbridge_bypass")
        self.assertEqual(ctx2.get("cve"), "CVE-2026-34780")


if __name__ == "__main__":
    unittest.main()
