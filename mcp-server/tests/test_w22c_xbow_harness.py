"""W22-c — XBOW Validation Benchmark harness tests."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class XbowToolsRegisteredTest(unittest.TestCase):

    def test_xbow_tools_registered(self):
        tools = server.mcp._tool_manager._tools
        self.assertIn("run_xbow_bench", tools)
        self.assertIn("xbow_pull_benchmarks", tools)
        self.assertIn("summarize_benchmarks", tools)


class XbowPullBenchmarksTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-xbow-pull-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_missing_git_returns_error(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=False):
            out = await captured["xbow_pull_benchmarks"](target_dir=str(self.tmp / "x"))
        self.assertIn("error", out)
        self.assertIn("git", out["error"].lower())

    async def test_clone_invocation_shape(self):
        """Verify the tool calls git clone with the right URL when target dir is empty."""
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        clone_calls = []

        async def fake_run_cmd(cmd, **kw):
            clone_calls.append(cmd)
            # Create empty target dir so the post-clone discovery sees nothing.
            target = cmd[-1] if cmd[0] == "git" and cmd[1] == "clone" else None
            if target:
                Path(target).mkdir(parents=True, exist_ok=True)
                (Path(target) / ".git").mkdir(exist_ok=True)
            return ("", "", 0)

        target = self.tmp / "xb"
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.benchmark._run_cmd", new=fake_run_cmd):
            out = await captured["xbow_pull_benchmarks"](target_dir=str(target))
        self.assertEqual(out["benchmark"], "XBOW")
        self.assertEqual(out["challenges_discovered"], 0)
        self.assertEqual(clone_calls[0][:2], ["git", "clone"])
        self.assertIn("xbow-engineering/validation-benchmarks",
                      clone_calls[0][-2])

    async def test_pull_existing_repo(self):
        """If repo already exists, tool should `git pull` not re-clone."""
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)

        target = self.tmp / "xb"
        target.mkdir(parents=True)
        (target / ".git").mkdir()
        # Seed two challenge dirs.
        for cid in ("XBEN-001-24", "XBEN-002-24"):
            cdir = target / "benchmarks" / cid
            cdir.mkdir(parents=True)
            (cdir / "benchmark.json").write_text(json.dumps({"name": cid, "level": 1}))

        calls = []

        async def fake_run_cmd(cmd, **kw):
            calls.append(cmd)
            return ("", "", 0)

        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.benchmark._run_cmd", new=fake_run_cmd):
            out = await captured["xbow_pull_benchmarks"](target_dir=str(target))
        self.assertEqual(out["action"], "pulled")
        self.assertEqual(out["challenges_discovered"], 2)
        # Verifies pull form, not clone.
        self.assertEqual(calls[0][0], "git")
        self.assertIn("pull", calls[0])


class RunXbowBenchTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-xbow-run-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_challenge(self, cid: str, level: int, win_cond: str) -> Path:
        cdir = self.tmp / "validation-benchmarks" / "benchmarks" / cid
        cdir.mkdir(parents=True)
        (cdir / "benchmark.json").write_text(json.dumps({
            "name": cid, "level": level, "win_condition": win_cond,
        }))
        return cdir

    async def test_missing_docker_returns_error(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=False):
            out = await captured["run_xbow_bench"](challenge_id="XBEN-001-24")
        self.assertIn("error", out)
        self.assertIn("docker", out["error"].lower())

    async def test_awaiting_grow_agent_when_no_flag(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        self._make_challenge("XBEN-001-24", 1, "FLAG{expected_value}")
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=True):
            out = await captured["run_xbow_bench"](challenge_id="XBEN-001-24")
        self.assertEqual(out["status"], "awaiting_grow_agent")
        self.assertEqual(out["level"], 1)
        self.assertTrue(out["expected_present"])

    async def test_passed_recorded_on_flag_match(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        cdir = self._make_challenge("XBEN-002-24", 2, "FLAG{match_me_now}")
        flag_file = self.tmp / ".burp-intel" / "_bench" / "xbow" / "XBEN-002-24-flag.txt"
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.write_text("FLAG{match_me_now}")
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.benchmark._intel_dir",
                   return_value=self.tmp / ".burp-intel"):
            out = await captured["run_xbow_bench"](challenge_id="XBEN-002-24")
        self.assertTrue(out["passed"])
        self.assertEqual(out["level"], 2)
        rec = json.loads(Path(out["record_path"]).read_text())
        self.assertEqual(rec["benchmark"], "XBOW")
        self.assertTrue(rec["passed"])

    async def test_failed_recorded_on_flag_mismatch(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        self._make_challenge("XBEN-003-24", 3, "FLAG{expected}")
        flag_file = self.tmp / ".burp-intel" / "_bench" / "xbow" / "XBEN-003-24-flag.txt"
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.write_text("FLAG{wrong_value}")
        with patch("burpsuite_mcp.tools.benchmark._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.benchmark._intel_dir",
                   return_value=self.tmp / ".burp-intel"):
            out = await captured["run_xbow_bench"](challenge_id="XBEN-003-24")
        self.assertFalse(out["passed"])
        self.assertEqual(out["level"], 3)


class SummarizeBenchmarksXbowBreakdownTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-xbow-sum-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_summarize_breaks_down_xbow_by_level(self):
        from burpsuite_mcp.tools import benchmark
        stub, captured = _stub_mcp()
        benchmark.register(stub)
        bench_root = self.tmp / ".burp-intel" / "_bench" / "xbow"
        bench_root.mkdir(parents=True)
        # Seed: L1 pass, L1 fail, L2 pass, L3 fail.
        for i, (level, passed) in enumerate([(1, True), (1, False), (2, True), (3, False)]):
            (bench_root / f"x{i}.json").write_text(json.dumps({
                "benchmark": "XBOW", "level": level, "passed": passed,
            }))
        with patch("burpsuite_mcp.tools.benchmark._intel_dir",
                   return_value=self.tmp / ".burp-intel"):
            out = await captured["summarize_benchmarks"]()
        xbow = out["benchmarks"]["xbow"]
        self.assertEqual(xbow["passed"], 2)
        self.assertEqual(xbow["failed"], 2)
        self.assertEqual(xbow["total"], 4)
        self.assertIn("by_level", xbow)
        self.assertEqual(xbow["by_level"]["1"], {"passed": 1, "failed": 1})
        self.assertEqual(xbow["by_level"]["2"], {"passed": 1, "failed": 0})
        self.assertEqual(xbow["by_level"]["3"], {"passed": 0, "failed": 1})


if __name__ == "__main__":
    unittest.main()
