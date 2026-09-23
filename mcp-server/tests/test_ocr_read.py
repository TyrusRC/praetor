"""read_screenshot_text — OCR-to-text tool (path resolution + graceful degrade)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from praetor import server
from praetor.tools.ocr_read import _resolve_screenshot_path


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class ResolveScreenshotPathTest(unittest.TestCase):
    def test_explicit_path_wins(self):
        p = _resolve_screenshot_path("/tmp/shot.png", "example.com", "other.png")
        self.assertEqual(p, Path("/tmp/shot.png"))

    def test_domain_and_filename_resolve_under_intel_dir(self):
        p = _resolve_screenshot_path("", "example.com", "burp-proxy-2024.png")
        self.assertEqual(
            p, Path.cwd() / ".burp-intel" / "example.com" / "screenshots" / "burp-proxy-2024.png")

    def test_filename_traversal_stripped_to_basename(self):
        p = _resolve_screenshot_path("", "example.com", "../../etc/passwd")
        self.assertEqual(p.name, "passwd")
        self.assertTrue(str(p).endswith("screenshots/passwd"))

    def test_neither_path_nor_domain_filename_is_none(self):
        self.assertIsNone(_resolve_screenshot_path("", "", ""))
        self.assertIsNone(_resolve_screenshot_path("", "example.com", ""))

    def test_invalid_domain_raises(self):
        with self.assertRaises(ValueError):
            _resolve_screenshot_path("", "foo..bar", "shot.png")


class ReadScreenshotTextToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_missing_file_returns_error(self):
        fn = _tool("read_screenshot_text")
        out = await fn(path="/nonexistent/shot.png")
        self.assertIn("error", out)
        self.assertIn("not found", out["error"])

    async def test_no_input_returns_error(self):
        fn = _tool("read_screenshot_text")
        out = await fn()
        self.assertIn("error", out)

    async def test_tesseract_missing_degrades_gracefully(self):
        fn = _tool("read_screenshot_text")
        with tempfile.NamedTemporaryFile(suffix=".png") as f:
            with patch("praetor.tools.ocr_read._tesseract_available", return_value=False):
                out = await fn(path=f.name)
        self.assertEqual(out["error"], "tesseract not installed")
        self.assertIn("hint", out)

    async def test_returns_ocr_text_from_mocked_tesseract(self):
        fn = _tool("read_screenshot_text")
        with tempfile.NamedTemporaryFile(suffix=".png") as f:
            with patch("praetor.tools.ocr_read._tesseract_available", return_value=True), \
                 patch("praetor.tools.ocr_read._run_tesseract_text",
                       return_value="Login\nUsername\nPassword\n/api/v1/admin"):
                out = await fn(path=f.name)
        self.assertEqual(out["text"], "Login\nUsername\nPassword\n/api/v1/admin")
        self.assertEqual(out["chars"], len(out["text"]))
        self.assertEqual(out["path"], f.name)


if __name__ == "__main__":
    unittest.main()
