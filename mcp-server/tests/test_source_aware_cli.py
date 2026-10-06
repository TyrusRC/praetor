"""vulnhuntr / xvulnhuntr wrappers use the REAL CLI, + ste-writer agent is discoverable.

The old wrappers passed flags that do not exist (--output, --repo, --output-format,
--max-files, --language) and would fail at argparse. These tests pin the correct flags
(-r, -a, -l, --llm), Go support, and the text-report fallback.
"""

import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import source_aware as SA

# A fake LLM key so the key pre-check passes and the CLI is built (the flag tests
# care about the command, not the key).
_KEYS = {"ANTHROPIC_API_KEY": "test", "OPENAI_API_KEY": "test"}


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class VulnhuntrCliTest(unittest.IsolatedAsyncioTestCase):

    async def _run(self, tool, **kw):
        captured = {}

        async def fake_run(cmd, timeout=0, bypass_proxy=False):
            captured["cmd"] = cmd
            return ('{"findings": []}', "", 0)   # JSON path

        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, _KEYS), \
             patch.object(SA, "_check_tool", return_value=True), \
             patch.object(SA, "_run_cmd", new=AsyncMock(side_effect=fake_run)):
            out = await _fn(tool)(repo_path=d, **kw)
        return captured.get("cmd", []), out

    async def test_vulnhuntr_real_flags(self):
        cmd, _ = await self._run("run_vulnhuntr", llm="gpt", analyze="app/views.py")
        self.assertEqual(cmd[:3], ["vulnhuntr", "-r", cmd[2]])
        self.assertIn("-l", cmd); self.assertIn("gpt", cmd)
        self.assertEqual(cmd[cmd.index("-a") + 1], "app/views.py")
        self.assertNotIn("--output", cmd)            # the bug: flag never existed

    async def test_xvulnhuntr_real_flags_and_go(self):
        cmd, _ = await self._run("run_xvulnhuntr", language="go", llm="claude")
        self.assertEqual(cmd[0], "xvulnhuntr")
        self.assertEqual(cmd[cmd.index("-l") + 1], "GO")      # language flag, uppercased
        self.assertEqual(cmd[cmd.index("--llm") + 1], "claude")
        self.assertNotIn("--repo", cmd)
        self.assertNotIn("--output-format", cmd)
        self.assertNotIn("--max-files", cmd)

    async def test_xvulnhuntr_bad_language_rejected(self):
        with tempfile.TemporaryDirectory() as d, patch.object(SA, "_check_tool", return_value=True):
            out = await _fn("run_xvulnhuntr")(repo_path=d, language="ruby")
        self.assertIn("language must be one of", out["error"])

    async def test_text_report_fallback_not_error(self):
        async def fake_run(cmd, timeout=0, bypass_proxy=False):
            return ("scratchpad: ...\nconfidence_score: 8\nvulnerability_types: [RCE]", "", 0)
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, _KEYS), \
             patch.object(SA, "_check_tool", return_value=True), \
             patch.object(SA, "_run_cmd", new=AsyncMock(side_effect=fake_run)):
            out = await _fn("run_vulnhuntr")(repo_path=d)
        self.assertEqual(out["format"], "text")       # not an error — report handed back
        self.assertIn("confidence_score", out["report"])

    async def test_missing_llm_key_gives_clean_hint(self):
        # No LLM key set -> clean hint, never a deep LLM-client failure.
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}, clear=False), \
             patch.object(SA, "_check_tool", return_value=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            out = await _fn("run_vulnhuntr")(repo_path=d, llm="claude")
        self.assertIn("no API key", out["error"])
        self.assertIn("ANTHROPIC_API_KEY", out["error"])


class SteWriterAgentTest(unittest.IsolatedAsyncioTestCase):

    async def test_agent_is_discoverable(self):
        out = await _fn("list_agents")()
        names = {a.get("name") for a in out.get("agents", [])}
        self.assertIn("ste-writer", names)


if __name__ == "__main__":
    unittest.main()
