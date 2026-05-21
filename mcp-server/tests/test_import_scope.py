"""import_scope: bulk add hosts from recon tool output."""
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import _scope_mode, scope_extra


def _get_tool():
    mcp = FastMCP("test")
    scope_extra.register(mcp)
    return mcp._tool_manager.get_tool("import_scope").fn


class ImportScopeTest(unittest.TestCase):
    def test_subfinder_txt(self):
        with NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("admin.acme.com\napi.acme.com\n\nmail.acme.com\n")
            path = f.name
        with patch("burpsuite_mcp.tools.scope_extra.client.post",
                   new=AsyncMock(return_value={"included": 3})):
            result = asyncio.run(_get_tool()(source=path, format="subfinder_txt"))
            self.assertIn("added: 3", result)

    def test_auto_format_sniff_plain(self):
        with NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://x.com\nhttps://y.com\n")
            path = f.name
        with patch("burpsuite_mcp.tools.scope_extra.client.post",
                   new=AsyncMock(return_value={"included": 2})):
            result = asyncio.run(_get_tool()(source=path, format="auto"))
            self.assertIn("plain", result)

    def test_httpx_json(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(json.dumps({"url": "https://a.example"}) + "\n")
            f.write(json.dumps({"url": "https://b.example"}) + "\n")
            path = f.name
        with patch("burpsuite_mcp.tools.scope_extra.client.post",
                   new=AsyncMock(return_value={"included": 2})):
            result = asyncio.run(_get_tool()(source=path, format="httpx_json"))
            self.assertIn("added: 2", result)


class ImportScopePreservesModeTest(unittest.TestCase):
    """Strict mode must survive import_scope — the prior bug hardcoded operator."""

    def test_strict_mode_preserved(self):
        # Run inside an isolated cwd so the real engagement state isn't touched.
        with tempfile.TemporaryDirectory() as tmpdir:
            prev_cwd = Path.cwd()
            os.chdir(tmpdir)
            try:
                _scope_mode.set_mode("strict")
                self.assertEqual(_scope_mode.get_mode(), "strict")

                with NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                    f.write("admin.acme.com\n")
                    src = f.name

                captured = {}

                async def fake_post(path, json):
                    captured["payload"] = json
                    return {"included": 1}

                with patch("burpsuite_mcp.tools.scope_extra.client.post",
                           new=AsyncMock(side_effect=fake_post)):
                    asyncio.run(_get_tool()(source=src, format="subfinder_txt"))

                self.assertEqual(captured["payload"]["mode"], "strict")
                # And the persisted mode is unchanged.
                self.assertEqual(_scope_mode.get_mode(), "strict")
            finally:
                os.chdir(prev_cwd)


if __name__ == "__main__":
    unittest.main()
