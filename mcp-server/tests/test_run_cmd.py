"""Regression test for _run_cmd stdin handling.

ProjectDiscovery tools (httpx, nuclei, katana, subfinder, gau,
waybackurls) auto-detect piped stdin and read URLs from it, ignoring
their -u / -list flags. When MCP server inherits stdin from the stdio
transport pipe, those tools hang indefinitely. This test asserts that
_run_cmd explicitly closes stdin so PD tools fall through to their
explicit-target paths.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch, MagicMock

from burpsuite_mcp.tools.recon import _common


class StdinHandling(unittest.TestCase):
    def test_run_cmd_passes_devnull_stdin(self):
        """The asyncio subprocess call MUST set stdin=DEVNULL.

        Without this, ProjectDiscovery tools (httpx, nuclei, etc.) auto-read
        the MCP stdio transport pipe and hang. Verify the kwarg is wired
        through correctly by intercepting create_subprocess_exec.
        """
        captured: dict = {}

        async def fake_proc(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            mock = MagicMock()

            async def communicate(input=None):
                captured["input"] = input
                return (b"", b"")
            mock.communicate = communicate
            mock.returncode = 0
            return mock

        with patch.object(_common.asyncio, "create_subprocess_exec",
                          side_effect=fake_proc):
            with patch.object(_common, "_find_tool", return_value="/usr/bin/true"):
                result = asyncio.run(_common._run_cmd(["true"], timeout=2))

        self.assertEqual(result[2], 0, "expected exit 0 from mocked proc")
        self.assertIn("stdin", captured["kwargs"],
                      "_run_cmd must explicitly pass stdin kwarg")
        self.assertEqual(captured["kwargs"]["stdin"],
                         asyncio.subprocess.DEVNULL,
                         "stdin must be DEVNULL to prevent PD tools from "
                         "auto-reading the MCP stdio pipe")
        self.assertIsNone(captured["input"], "no stdin_input -> input None")

    def test_run_cmd_stdin_input_opens_pipe(self):
        """stdin_input must open a PIPE and be fed to communicate()."""
        captured: dict = {}

        async def fake_proc(*args, **kwargs):
            captured["kwargs"] = kwargs
            mock = MagicMock()

            async def communicate(input=None):
                captured["input"] = input
                return (b"ok", b"")
            mock.communicate = communicate
            mock.returncode = 0
            return mock

        with patch.object(_common.asyncio, "create_subprocess_exec",
                          side_effect=fake_proc):
            with patch.object(_common, "_find_tool", return_value="/usr/bin/peirates"):
                result = asyncio.run(
                    _common._run_cmd(["peirates"], timeout=2, stdin_input=b"1\nexit\n"))

        self.assertEqual(result, ("ok", "", 0))
        self.assertEqual(captured["kwargs"]["stdin"], asyncio.subprocess.PIPE,
                         "stdin_input must switch stdin to PIPE")
        self.assertEqual(captured["input"], b"1\nexit\n")


if __name__ == "__main__":
    unittest.main()
