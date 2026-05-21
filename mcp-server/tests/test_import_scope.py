"""import_scope: bulk add hosts from recon tool output."""
import asyncio
import json
import unittest
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import scope_extra


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


if __name__ == "__main__":
    unittest.main()
