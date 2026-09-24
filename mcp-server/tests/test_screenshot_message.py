"""screenshot_message wiring — auto keyword pick + POST to the editor-search handler."""

import base64
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from praetor.tools import burp_ui

# 1x1 transparent PNG so _save_shot has a decodable image to write.
_PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
            "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _resolve():
    from praetor import server
    return server.mcp._tool_manager._tools["screenshot_message"].fn


class ScreenshotMessageTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="shot-msg-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_auto_keyword_from_response_and_post(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"
        detail = {"status_code": 200, "response_headers": [{"name": "Set-Cookie",
                  "value": f"jwt={jwt}; Path=/"}], "response_body": "ok"}
        posted = {}

        async def fake_get(path, **kw):
            return detail

        async def fake_post(path, json=None):
            posted["path"] = path
            posted["json"] = json
            return {"png_base64": _PNG_B64, "width": 10, "height": 10,
                    "which": json["which"], "search": json["search"],
                    "engine": "editor-search"}

        with patch.object(burp_ui.client, "get", new=AsyncMock(side_effect=fake_get)), \
             patch.object(burp_ui.client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _resolve()(proxy_history_index=7, domain="t.example")

        self.assertEqual(posted["path"], "/api/ui/message-screenshot")
        self.assertEqual(posted["json"]["proxy_index"], 7)
        self.assertEqual(posted["json"]["which"], "both")   # default request+response
        self.assertTrue(posted["json"]["search"].startswith("eyJ"))  # JWT auto-picked from response
        self.assertEqual(out["search_reason"], "jwt")
        self.assertEqual(out["engine"], "editor-search")
        self.assertTrue(Path(out["saved"]).exists())

    async def test_explicit_search_skips_detail_fetch(self):
        posted = {}

        async def boom(*a, **k):
            raise AssertionError("detail should not be fetched when search is explicit")

        async def fake_post(path, json=None):
            posted["json"] = json
            return {"png_base64": _PNG_B64, "width": 10, "height": 10,
                    "which": "request", "search": json["search"], "engine": "editor-search"}

        with patch.object(burp_ui.client, "get", new=AsyncMock(side_effect=boom)), \
             patch.object(burp_ui.client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _resolve()(proxy_history_index=2, domain="t.example",
                                   which="request", search="{{7*7}}")

        self.assertEqual(posted["json"]["search"], "{{7*7}}")
        self.assertEqual(posted["json"]["which"], "request")
        self.assertEqual(out["search_reason"], "explicit")

    async def test_negative_index_rejected(self):
        out = await _resolve()(proxy_history_index=-1)
        self.assertIn("error", out)

    async def test_detail_error_propagates(self):
        async def fake_get(path, **kw):
            return {"error": "index out of range"}

        with patch.object(burp_ui.client, "get", new=AsyncMock(side_effect=fake_get)):
            out = await _resolve()(proxy_history_index=999, domain="t.example")
        self.assertEqual(out.get("error"), "index out of range")


if __name__ == "__main__":
    unittest.main()
