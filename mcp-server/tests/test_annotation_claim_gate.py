"""Claim-color gating on bulk annotation + Burp-verified tag recording.

annotate_request already refused an unbacked RED/ORANGE; annotate_bulk did not,
so a batch was a way around the gate. And nothing recorded what Burp actually
stored, which is how a writeup cites a comment the history never had.
"""

import asyncio
import json
import unittest
from unittest import mock

from mcp.server.fastmcp import FastMCP

from praetor.tools import proxy_control
from praetor.tools.notes._projection import render_finding_md


def _bulk_tool():
    mcp = FastMCP("t")
    with mock.patch.object(proxy_control._annotate, "client"):
        proxy_control.register(mcp)
    return mcp._tool_manager.get_tool("annotate_bulk").fn


class TestBulkClaimGate(unittest.TestCase):
    def setUp(self):
        self.bulk = _bulk_tool()

    def _run(self, items, **kw):
        return asyncio.run(self.bulk(items, **kw))

    def test_unbacked_claim_color_blocks_the_whole_batch(self):
        with mock.patch.object(proxy_control._annotate, "client") as c:
            out = self._run([{"index": 1, "color": "RED", "comment": "sqli"}])
            c.post.assert_not_called()
        self.assertIn("QUESTION GATE", out)
        self.assertIn("nothing annotated", out)

    def test_nonclaim_colors_pass_through(self):
        async def fake_post(*_a, **_k):
            return {"applied": 2, "errors": []}
        with mock.patch.object(proxy_control._annotate, "client") as c:
            c.post = fake_post
            out = self._run([
                {"index": 1, "color": "YELLOW"},
                {"index": 2, "color": "GRAY"},
            ])
        self.assertIn("Annotated 2 of 2", out)

    def test_confirm_true_allows_claim_colors(self):
        async def fake_post(*_a, **_k):
            return {"applied": 1, "errors": []}
        with mock.patch.object(proxy_control._annotate, "client") as c:
            c.post = fake_post
            out = self._run([{"index": 1, "color": "RED"}], confirm=True)
        self.assertIn("Annotated 1 of 1", out)

    def test_unknown_finding_id_blocks_even_with_confirm(self):
        with mock.patch.object(proxy_control._annotate, "_lookup_finding_id", return_value=(False, "")):
            with mock.patch.object(proxy_control._annotate, "client") as c:
                out = self._run(
                    [{"index": 1, "color": "RED", "finding_id": "f999"}], confirm=True
                )
                c.post.assert_not_called()
        self.assertIn("does not exist", out)

    def test_resolvable_finding_id_passes_without_confirm(self):
        async def fake_post(*_a, **_k):
            return {"applied": 1, "errors": []}
        with mock.patch.object(proxy_control._annotate, "_lookup_finding_id", return_value=(True, "ex.com T")):
            with mock.patch.object(proxy_control._annotate, "client") as c:
                c.post = fake_post
                out = self._run([{"index": 1, "color": "RED", "finding_id": "f001"}])
        self.assertIn("Annotated 1 of 1", out)

    def test_non_dict_items_do_not_crash_the_gate(self):
        async def fake_post(*_a, **_k):
            return {"applied": 0, "errors": []}
        with mock.patch.object(proxy_control._annotate, "client") as c:
            c.post = fake_post
            self._run(["garbage", None])  # must not raise


class TestAnnotationRecording(unittest.TestCase):
    def test_read_back_is_stored_and_re_annotation_replaces(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dom = root / "ex.com"
            dom.mkdir()
            store = {"findings": [{"id": "f001", "title": "T"}]}
            (dom / "findings.json").write_text(json.dumps(store), encoding="utf-8")

            with mock.patch("praetor.tools.notes._helpers._intel_dir", return_value=root):
                proxy_control._record_annotation_on_finding(
                    "f001", {"index": 7, "color": "RED", "comment": "stored text"}
                )
                proxy_control._record_annotation_on_finding(
                    "f001", {"index": 7, "color": "ORANGE", "comment": "revised"}
                )

            got = json.loads((dom / "findings.json").read_text())["findings"][0]["annotations"]
        self.assertEqual(len(got), 1, "re-annotating the same index must replace, not stack")
        self.assertEqual(got[0]["color"], "ORANGE")
        self.assertEqual(got[0]["comment"], "revised")

    def test_missing_store_is_silent(self):
        from pathlib import Path
        with mock.patch("praetor.tools.notes._helpers._intel_dir",
                        return_value=Path("/nonexistent-praetor-test")):
            proxy_control._record_annotation_on_finding("f001", {"index": 1})

    def test_projection_renders_only_verified_tags(self):
        md = render_finding_md({
            "id": "f001", "title": "T", "severity": "HIGH",
            "annotations": [{"index": 7, "color": "RED", "comment": "stored text",
                             "method": "GET", "url": "https://ex.com/api/x"}],
        })
        self.assertIn("read back from the live history", md)
        self.assertIn("#7 [RED] stored text", md)

    def test_projection_omits_the_section_with_no_verified_tags(self):
        md = render_finding_md({"id": "f001", "title": "T", "severity": "HIGH"})
        self.assertNotIn("Burp Annotations", md)


if __name__ == "__main__":
    unittest.main()
