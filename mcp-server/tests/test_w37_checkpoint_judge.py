"""W37 — durable engagement checkpoint (A) + independent completion judge (B).

Pure filesystem coverage: no Burp client, no network. Exercises the real merge /
dedupe / gap logic, not wiring.

Covers:
  A. intel/checkpoint: merge_checkpoint field-level merge (scalars, task-by-id,
     open_threads dedupe + explicit clear), load_checkpoint_data absence/bad
     domain, hierarchical task ids.
  B. report/completion_judge: judge_completion_data gap assembly — checkpoint
     absence, open tasks, open threads, business-logic gate, coverage presence;
     complete only when every gate clears.
"""

from __future__ import annotations

import json
import shutil
import unittest

from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized


class _ToolCapture:
    """Minimal FastMCP stand-in: capture @mcp.tool()-decorated coroutines."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *args, **kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


# ---------------------------------------------------------------------------
# A. checkpoint — merge semantics
# ---------------------------------------------------------------------------
class CheckpointMergeTest(unittest.TestCase):
    DOMAIN = "w37-ckpt.test-throwaway.example"

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def _path(self):
        from burpsuite_mcp.tools.intel.checkpoint import _checkpoint_path
        return _checkpoint_path(self.DOMAIN)

    def test_absent_returns_empty(self):
        from burpsuite_mcp.tools.intel.checkpoint import load_checkpoint_data
        self.assertEqual(load_checkpoint_data(self.DOMAIN), {})

    def test_bad_domain_is_safe(self):
        # Traversal-shaped domains that _sanitized rejects (contain '..' or empty)
        # must return {} without writing, never raise.
        from burpsuite_mcp.tools.intel.checkpoint import (
            load_checkpoint_data, merge_checkpoint)
        for bad in ("..", "a/../../etc", ""):
            self.assertEqual(load_checkpoint_data(bad), {})
            self.assertEqual(merge_checkpoint(bad, phase="scan"), {})

    def test_scalars_overwrite_only_when_supplied(self):
        from burpsuite_mcp.tools.intel.checkpoint import (
            merge_checkpoint, load_checkpoint_data)
        merge_checkpoint(self.DOMAIN, phase="recon", round=1,
                         next_action="crawl", objective="broad coverage")
        # Partial write: only round advances; empty scalars must NOT blank fields.
        merge_checkpoint(self.DOMAIN, round=2)
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["round"], 2)
        self.assertEqual(d["phase"], "recon")
        self.assertEqual(d["next_action"], "crawl")
        self.assertEqual(d["objective"], "broad coverage")

    def test_tasks_merge_by_id_field_level(self):
        from burpsuite_mcp.tools.intel.checkpoint import (
            merge_checkpoint, load_checkpoint_data)
        merge_checkpoint(self.DOMAIN, tasks=[
            {"id": "T1", "title": "recon surface", "status": "in_progress", "note": "start"},
            {"id": "T1.1", "title": "js secrets", "status": "pending"},
        ])
        # Flip T1 status only — title + note must survive; add a new T2.
        merge_checkpoint(self.DOMAIN, tasks=[
            {"id": "T1", "status": "done"},
            {"id": "T2", "title": "sqli sweep", "status": "in_progress"},
        ])
        d = load_checkpoint_data(self.DOMAIN)
        by_id = {t["id"]: t for t in d["tasks"]}
        self.assertEqual(by_id["T1"]["status"], "done")
        self.assertEqual(by_id["T1"]["title"], "recon surface")  # preserved
        self.assertEqual(by_id["T1"]["note"], "start")           # preserved
        self.assertEqual(by_id["T1.1"]["status"], "pending")     # untouched
        self.assertEqual(by_id["T2"]["title"], "sqli sweep")     # appended
        # Order preserved: existing first, new appended.
        self.assertEqual([t["id"] for t in d["tasks"]], ["T1", "T1.1", "T2"])

    def test_invalid_status_normalises_to_pending(self):
        from burpsuite_mcp.tools.intel.checkpoint import (
            merge_checkpoint, load_checkpoint_data)
        merge_checkpoint(self.DOMAIN, tasks=[{"id": "T1", "status": "wat"}])
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["tasks"][0]["status"], "pending")

    def test_open_threads_dedupe_and_explicit_clear(self):
        from burpsuite_mcp.tools.intel.checkpoint import (
            merge_checkpoint, load_checkpoint_data)
        merge_checkpoint(self.DOMAIN, open_threads=["a", "b"])
        merge_checkpoint(self.DOMAIN, open_threads=["b", "c"])  # b is dup
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["open_threads"], ["a", "b", "c"])
        # None = leave unchanged.
        merge_checkpoint(self.DOMAIN, phase="verify")
        self.assertEqual(load_checkpoint_data(self.DOMAIN)["open_threads"], ["a", "b", "c"])
        # Explicit [] clears.
        merge_checkpoint(self.DOMAIN, open_threads=[])
        self.assertEqual(load_checkpoint_data(self.DOMAIN)["open_threads"], [])

    def test_tool_wrappers_roundtrip(self):
        import asyncio
        from burpsuite_mcp.tools.intel import checkpoint as mod
        cap = _ToolCapture()
        mod.register(cap)
        write = cap.tools["write_checkpoint"]
        load = cap.tools["load_checkpoint"]
        out = asyncio.run(write(self.DOMAIN, phase="scan", round=3,
                                next_action="dispatch verifier",
                                tasks=[{"id": "T1", "title": "x", "status": "done"}]))
        self.assertIn("phase=scan", out)
        summary = asyncio.run(load(self.DOMAIN))
        self.assertIn("dispatch verifier", summary)
        self.assertIn("T1", summary)
        # Fresh domain -> new-target notice.
        self.assertIn("fresh engagement",
                      asyncio.run(load("w37-nope.test-throwaway.example")).lower())


# ---------------------------------------------------------------------------
# B. completion_judge — gap assembly
# ---------------------------------------------------------------------------
class CompletionJudgeTest(unittest.TestCase):
    DOMAIN = "w37-judge.test-throwaway.example"

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def _write_json(self, name: str, payload: dict) -> None:
        from burpsuite_mcp.tools.workspace import workspace_paths
        root = workspace_paths(self.DOMAIN)["root"]
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(json.dumps(payload), encoding="utf-8")

    def test_no_checkpoint_is_incomplete(self):
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        v = judge_completion_data(self.DOMAIN)
        self.assertFalse(v["complete"])
        self.assertTrue(any("no checkpoint" in g for g in v["gaps"]))

    def test_open_task_blocks_completion(self):
        from burpsuite_mcp.tools.intel.checkpoint import merge_checkpoint
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        merge_checkpoint(self.DOMAIN, phase="scan",
                         tasks=[{"id": "T1", "title": "sqli", "status": "in_progress"}])
        v = judge_completion_data(self.DOMAIN)
        self.assertFalse(v["complete"])
        self.assertEqual(v["open_tasks"][0]["id"], "T1")
        self.assertTrue(any("open task T1" in g for g in v["gaps"]))

    def test_open_thread_blocks_completion(self):
        from burpsuite_mcp.tools.intel.checkpoint import merge_checkpoint
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        merge_checkpoint(self.DOMAIN, tasks=[{"id": "T1", "status": "done"}],
                         open_threads=["500 on /api/export — revisit SSTI"])
        v = judge_completion_data(self.DOMAIN)
        self.assertFalse(v["complete"])
        self.assertTrue(any("unresolved thread" in g for g in v["gaps"]))

    def test_complete_when_all_gates_clear(self):
        from burpsuite_mcp.tools.intel.checkpoint import merge_checkpoint
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        # All tasks done, no threads.
        merge_checkpoint(self.DOMAIN, phase="done",
                         tasks=[{"id": "T1", "status": "done"},
                                {"id": "T2", "status": "done"}])
        # Coverage recorded.
        self._write_json("coverage.json", {"knowledge_version": "1", "entries": [{"x": 1}]})
        # One confirmed finding.
        self._write_json("findings.json", {"findings": [
            {"id": "f-1", "status": "confirmed", "severity": "HIGH"}]})
        # Business-logic pass proven (>=1 tested invariant).
        from burpsuite_mcp.tools.report import business_logic_gate as blg
        cap = _ToolCapture()
        blg.register(cap)
        import asyncio
        asyncio.run(cap.tools["record_business_logic_test"](
            self.DOMAIN, "coupon one-use", "/api/redeem", "held", True))

        v = judge_completion_data(self.DOMAIN)
        self.assertTrue(v["complete"], v["gaps"])
        self.assertEqual(v["confirmed_findings"], 1)
        self.assertIn("generate_report", v["recommended_next"])

    def test_missing_coverage_and_bizlogic_are_gaps(self):
        from burpsuite_mcp.tools.intel.checkpoint import merge_checkpoint
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        merge_checkpoint(self.DOMAIN, phase="done",
                         tasks=[{"id": "T1", "status": "done"}])
        v = judge_completion_data(self.DOMAIN)
        self.assertFalse(v["complete"])
        self.assertTrue(any("no coverage" in g for g in v["gaps"]))
        self.assertTrue(any("business-logic" in g for g in v["gaps"]))

    def test_empty_domain_safe(self):
        from burpsuite_mcp.tools.report.completion_judge import judge_completion_data
        v = judge_completion_data("")
        self.assertFalse(v["complete"])


if __name__ == "__main__":
    unittest.main()
