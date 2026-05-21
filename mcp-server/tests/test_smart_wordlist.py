"""Smart wordlist generator: tech-aware SecLists slicing + recon-derived priority."""
import asyncio
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import wordlist


def _get_tool():
    mcp = FastMCP("test")
    wordlist.register(mcp)
    return mcp._tool_manager.get_tool("generate_smart_wordlist").fn


class SmartWordlistTest(unittest.TestCase):
    def _setup_target(self, tmp: Path, tech: list[str], endpoints: list[str]):
        intel = tmp / ".burp-intel" / "example.com"
        intel.mkdir(parents=True)
        (intel / "fingerprint.json").write_text(json.dumps({"tech_stack": tech}))
        (intel / "endpoints.json").write_text(json.dumps({"endpoints": endpoints}))

    def test_php_fingerprint_includes_php_slice(self):
        with TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            self._setup_target(tmpp, ["PHP"], ["/login.php", "/admin/index.php"])
            seclists = tmpp / "seclists"
            (seclists / "Discovery" / "Web-Content").mkdir(parents=True)
            (seclists / "Discovery" / "Web-Content" / "PHP.fuzz.txt").write_text(
                "wp-config.php\nphpinfo.php\n"
            )
            (seclists / "Discovery" / "Web-Content" / "common.txt").write_text(
                "robots.txt\nsitemap.xml\n"
            )
            with mock.patch("burpsuite_mcp.tools.wordlist._cwd", lambda: tmpp), \
                 mock.patch("burpsuite_mcp.tools.wordlist.detect_seclists", lambda: str(seclists)):
                out = asyncio.run(_get_tool()(domain="example.com", tier="shallow"))
                self.assertIn("path", out)
                p = Path(out["path"])
                content = p.read_text()
                self.assertIn("wp-config.php", content)
                self.assertIn("login.php", content)  # recon-derived
                self.assertGreater(out["breakdown"]["recon"], 0)
                self.assertGreater(out["breakdown"]["tech"], 0)

    def test_tiers_monotonic(self):
        with TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            self._setup_target(tmpp, ["PHP"], [])
            seclists = tmpp / "seclists"
            (seclists / "Discovery" / "Web-Content").mkdir(parents=True)
            (seclists / "Discovery" / "Web-Content" / "PHP.fuzz.txt").write_text(
                "\n".join(f"php-{i}" for i in range(20))
            )
            (seclists / "Discovery" / "Web-Content" / "common.txt").write_text(
                "\n".join(f"c-{i}" for i in range(50))
            )
            (seclists / "Discovery" / "Web-Content" / "directory-list-2.3-small.txt").write_text(
                "\n".join(f"d-{i}" for i in range(200))
            )
            with mock.patch("burpsuite_mcp.tools.wordlist._cwd", lambda: tmpp), \
                 mock.patch("burpsuite_mcp.tools.wordlist.detect_seclists", lambda: str(seclists)):
                shallow = asyncio.run(_get_tool()(domain="example.com", tier="shallow"))
                medium = asyncio.run(_get_tool()(domain="example.com", tier="medium"))
                self.assertLess(shallow["total"], medium["total"])

    def test_no_fingerprint_uses_generic(self):
        with TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            intel = tmpp / ".burp-intel" / "example.com"
            intel.mkdir(parents=True)
            seclists = tmpp / "seclists"
            (seclists / "Discovery" / "Web-Content").mkdir(parents=True)
            (seclists / "Discovery" / "Web-Content" / "common.txt").write_text("robots.txt\n")
            with mock.patch("burpsuite_mcp.tools.wordlist._cwd", lambda: tmpp), \
                 mock.patch("burpsuite_mcp.tools.wordlist.detect_seclists", lambda: str(seclists)):
                out = asyncio.run(_get_tool()(domain="example.com", tier="shallow"))
                self.assertEqual(out["breakdown"]["tech"], 0)
                self.assertGreater(out["breakdown"]["generic"], 0)

    def test_missing_seclists_returns_error(self):
        with TemporaryDirectory() as tmp:
            tmpp = Path(tmp)
            self._setup_target(tmpp, ["PHP"], [])
            with mock.patch("burpsuite_mcp.tools.wordlist._cwd", lambda: tmpp), \
                 mock.patch("burpsuite_mcp.tools.wordlist.detect_seclists", lambda: None):
                out = asyncio.run(_get_tool()(domain="example.com", tier="shallow"))
                self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
