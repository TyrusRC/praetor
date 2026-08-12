"""FP-delete + prune: ID compaction, chain_with rewrite, max+1 assignment."""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.notes._helpers import (
    _compact_and_remap_findings,
    _safe_findings_path,
)
from burpsuite_mcp.tools.report.lifecycle import purge_false_positives


def _make_finding(fid: str, status: str = "confirmed", chain=None, conf: float = 0.5) -> dict:
    return {
        "id": fid,
        "title": f"finding {fid}",
        "description": "x",
        "severity": "MEDIUM",
        "endpoint": f"https://t.example/{fid}",
        "evidence": {"logger_index": 1},
        "evidence_text": "",
        "status": status,
        "parameter": "p",
        "vuln_type": "xss",
        "confidence": conf,
        "chain_with": chain or [],
        "reproductions": [],
        "human_verified": False,
        "overrides": [],
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "burp_id": "",
    }


def _seed(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"findings": findings, "last_modified": ""}, indent=2))


class CompactAndRemapTest(unittest.TestCase):

    def test_contiguous_already_no_remap(self):
        findings = [_make_finding("f001"), _make_finding("f002"), _make_finding("f003")]
        out, id_map = _compact_and_remap_findings(findings)
        self.assertEqual([f["id"] for f in out], ["f001", "f002", "f003"])
        self.assertEqual(id_map, {"f001": "f001", "f002": "f002", "f003": "f003"})

    def test_gap_compacted(self):
        # f002 deleted upstream; helper receives [f001, f003].
        findings = [_make_finding("f001"), _make_finding("f003")]
        out, id_map = _compact_and_remap_findings(findings)
        self.assertEqual([f["id"] for f in out], ["f001", "f002"])
        self.assertEqual(id_map["f003"], "f002")

    def test_chain_with_remapped(self):
        # f003 chained to f001; after f002 delete, f003 becomes f002; chain_with stays valid.
        findings = [
            _make_finding("f001"),
            _make_finding("f003", chain=["f001"]),
        ]
        out, _ = _compact_and_remap_findings(findings)
        self.assertEqual(out[1]["chain_with"], ["f001"])
        self.assertEqual(out[1]["id"], "f002")

    def test_chain_with_dead_ref_dropped(self):
        # f002 was deleted; survivor f003's chain_with=['f002'] -> dropped.
        findings = [
            _make_finding("f001"),
            _make_finding("f003", chain=["f002", "f001"]),
        ]
        out, _ = _compact_and_remap_findings(findings)
        self.assertEqual(out[1]["chain_with"], ["f001"])

    def test_chain_with_renumber_internal(self):
        # f001 chains to f003; both kept; renumbered to f001, f002; chain updates.
        findings = [
            _make_finding("f001", chain=["f003"]),
            _make_finding("f003"),
        ]
        out, _ = _compact_and_remap_findings(findings)
        self.assertEqual(out[0]["chain_with"], ["f002"])


class HardDeleteCompactsTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="burp-intel-remap-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_hard_delete_compacts_and_remaps_chain(self):
        from burpsuite_mcp.tools.notes._helpers import _hard_delete_finding
        domain = "t.example"
        path = _safe_findings_path(domain)
        _seed(path, [
            _make_finding("f001"),
            _make_finding("f002", conf=0.3),
            _make_finding("f003", chain=["f001", "f002"]),
        ])
        target = json.loads(path.read_text())["findings"][1]
        with patch(
            "burpsuite_mcp.tools.notes._helpers.client.delete",
            new=AsyncMock(return_value={"ok": True}),
        ):
            deleted, _ = await _hard_delete_finding(domain, target)
        self.assertTrue(deleted)
        stored = json.loads(path.read_text())["findings"]
        self.assertEqual([f["id"] for f in stored], ["f001", "f002"])
        # f003 -> f002, its chain ['f001','f002'(deleted)] -> ['f001']
        self.assertEqual(stored[1]["chain_with"], ["f001"])


class PurgeFalsePositivesCompactsTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="burp-intel-purge-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_purge_compacts_survivors(self):
        domain = "t.example"
        path = _safe_findings_path(domain)
        _seed(path, [
            _make_finding("f001"),
            _make_finding("f002", status="likely_false_positive"),
            _make_finding("f003", chain=["f001", "f002"]),
            _make_finding("f004", status="likely_false_positive"),
            _make_finding("f005"),
        ])
        keep, deleted = await purge_false_positives(domain)
        self.assertEqual(deleted, 2)
        stored = json.loads(path.read_text())["findings"]
        self.assertEqual([f["id"] for f in stored], ["f001", "f002", "f003"])
        # f003 was 3rd kept survivor -> renumbered f003; its chain dropped the FP.
        self.assertEqual(stored[1]["chain_with"], ["f001"])


class SaveFindingIdMaxPlusOneTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="burp-intel-save-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_save_finding_does_not_refill_gap(self):
        """If on-disk store is f001, f003 (gap at f002 — e.g. raw edit bypassed
        compaction), next save MUST become f004, NOT refill f002."""

        domain = "t.example"
        path = _safe_findings_path(domain)
        _seed(path, [_make_finding("f001"), _make_finding("f003")])

        # Bypass recon gate + Burp API.
        with patch(
            "burpsuite_mcp.tools.notes.save.client.post",
            new=AsyncMock(return_value={"id": "burp-99"}),
        ), patch(
            "burpsuite_mcp.tools.intel.recon_gate_check",
            return_value=None,
        ):
            save_fn = server.mcp._tool_manager._tools["save_finding"].fn
            out = await save_fn(
                title="new",
                description="x",
                evidence={"logger_index": 5},
                severity="LOW",
                endpoint="https://t.example/new",
                parameter="q",
                vuln_type="xss",
                domain=domain,
                confidence=0.4,
                force_recon_gate=True,
                # The seeded findings are the same class at other endpoints, so
                # the systemic-duplicate gate would (correctly) stop this save.
                # This test is about ID allocation; opt out to reach that path.
                overrides=["systemic_dup:id-allocation test fixture"],
            )
        self.assertIn("f004", out)
        stored_ids = [f["id"] for f in json.loads(path.read_text())["findings"]]
        self.assertIn("f004", stored_ids)
        self.assertNotIn("f002", stored_ids)


class PruneFindingsToolTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="burp-intel-prune-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_prune_dry_run_does_not_mutate(self):
        domain = "t.example"
        path = _safe_findings_path(domain)
        _seed(path, [
            _make_finding("f001"),
            _make_finding("f002", status="suspected"),
        ])
        prune_fn = server.mcp._tool_manager._tools["prune_findings"].fn
        out = await prune_fn(domain=domain)
        self.assertIn("DRY-RUN", out)
        stored = json.loads(path.read_text())["findings"]
        self.assertEqual(len(stored), 2)

    async def test_prune_drops_non_confirmed_and_compacts(self):
        domain = "t.example"
        path = _safe_findings_path(domain)
        _seed(path, [
            _make_finding("f001"),
            _make_finding("f002", status="suspected"),
            _make_finding("f003", chain=["f001", "f002"]),
            _make_finding("f004", status="stale"),
        ])
        prune_fn = server.mcp._tool_manager._tools["prune_findings"].fn
        out = await prune_fn(domain=domain, confirm=True)
        self.assertIn("Pruned 2 of 4", out)
        stored = json.loads(path.read_text())["findings"]
        self.assertEqual([f["id"] for f in stored], ["f001", "f002"])
        # f003 -> f002; chain ref to pruned f002 (suspected) dropped.
        self.assertEqual(stored[1]["chain_with"], ["f001"])


def _ann(index: int, fid: str, extra: str = "reflected") -> dict:
    return {"index": index, "color": "RED", "comment": f"{fid} | xss | {extra}",
            "url": "https://t.example/x", "method": "GET"}


class AnnotationRemapImpactTest(unittest.TestCase):
    """Pure question-gate preview: which report comments a renumber would stale."""

    def test_impact_lists_only_renumbered_findings_with_annotations(self):
        from burpsuite_mcp.tools.notes._helpers import (
            _annotation_remap_impact,
            _prospective_id_map,
        )
        f1 = _make_finding("f001")                       # id unchanged
        f3 = _make_finding("f003")                       # will renumber -> f002
        f3["annotations"] = [_ann(2, "f003"), _ann(9, "f003", "second step")]
        keep = [f1, f3]
        id_map = _prospective_id_map(keep)
        self.assertEqual(id_map, {"f001": "f001", "f003": "f002"})
        impact = _annotation_remap_impact(keep, id_map)
        self.assertEqual(len(impact), 1)
        self.assertEqual(impact[0]["old"], "f003")
        self.assertEqual(impact[0]["new"], "f002")
        self.assertEqual(impact[0]["indices"], [2, 9])

    def test_no_impact_when_no_annotations(self):
        from burpsuite_mcp.tools.notes._helpers import (
            _annotation_remap_impact,
            _prospective_id_map,
        )
        keep = [_make_finding("f001"), _make_finding("f003")]
        self.assertEqual(_annotation_remap_impact(keep, _prospective_id_map(keep)), [])


class ResyncBurpAnnotationsTest(unittest.IsolatedAsyncioTestCase):

    async def test_rewrites_id_token_and_stores_readback(self):
        from burpsuite_mcp.tools.notes import _helpers
        f = _make_finding("f003")
        f["id"] = "f002"  # already renumbered by compact
        f["annotations"] = [_ann(2, "f003")]

        def fake_post(path, json=None):
            # Burp echoes back what it stored (the read-back).
            return {"notes": json["comment"], "color": json["color"], "index": json["index"]}

        with patch.object(_helpers.client, "post", new=AsyncMock(side_effect=fake_post)):
            summary = await _helpers.resync_burp_annotations([f], {"f003": "f002"})

        self.assertEqual(summary["resynced"], 1)
        self.assertEqual(summary["unreachable"], 0)
        # comment token rewritten f003 -> f002, stored from read-back
        self.assertEqual(f["annotations"][0]["comment"], "f002 | xss | reflected")

    async def test_burp_unreachable_counts_and_leaves_comment(self):
        from burpsuite_mcp.tools.notes import _helpers
        f = _make_finding("f003")
        f["id"] = "f002"
        f["annotations"] = [_ann(2, "f003")]

        with patch.object(_helpers.client, "post",
                          new=AsyncMock(return_value={"error": "ConnectTimeout"})):
            summary = await _helpers.resync_burp_annotations([f], {"f003": "f002"})

        self.assertEqual(summary["resynced"], 0)
        self.assertEqual(summary["unreachable"], 1)
        # left as-is for a later manual re-annotate
        self.assertEqual(f["annotations"][0]["comment"], "f003 | xss | reflected")

    async def test_noop_when_nothing_renumbered(self):
        from burpsuite_mcp.tools.notes import _helpers
        f = _make_finding("f001")
        f["annotations"] = [_ann(2, "f001")]
        with patch.object(_helpers.client, "post", new=AsyncMock()) as m:
            summary = await _helpers.resync_burp_annotations([f], {"f001": "f001"})
        m.assert_not_awaited()
        self.assertEqual(summary["resynced"], 0)


class PruneResyncsBurpHistoryTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="burp-intel-prune-ann-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_dry_run_reports_history_impact(self):
        domain = "t.example"
        path = _safe_findings_path(domain)
        f3 = _make_finding("f003")
        f3["annotations"] = [_ann(2, "f003")]
        _seed(path, [_make_finding("f001"),
                     _make_finding("f002", status="suspected"), f3])
        prune_fn = server.mcp._tool_manager._tools["prune_findings"].fn
        out = await prune_fn(domain=domain)  # dry-run
        self.assertIn("DRY-RUN", out)
        self.assertIn("BURP HISTORY IMPACT", out)
        self.assertIn("f003 -> f002", out)
        # nothing mutated
        self.assertEqual(len(json.loads(path.read_text())["findings"]), 3)

    async def test_confirm_rewrites_and_persists_comment(self):
        from burpsuite_mcp.tools.notes import _helpers
        domain = "t.example"
        path = _safe_findings_path(domain)
        f3 = _make_finding("f003")
        f3["annotations"] = [_ann(2, "f003")]
        _seed(path, [_make_finding("f001"),
                     _make_finding("f002", status="suspected"), f3])

        def fake_post(p, json=None):
            return {"notes": json["comment"], "color": json["color"], "index": json["index"]}

        prune_fn = server.mcp._tool_manager._tools["prune_findings"].fn
        with patch.object(_helpers.client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await prune_fn(domain=domain, confirm=True)

        self.assertIn("Pruned 1 of 3", out)
        self.assertIn("Burp history: 1 comment(s) rewritten", out)
        stored = json.loads(path.read_text())["findings"]
        # f003 renumbered to f002; its stored comment now cites f002
        f002 = next(f for f in stored if f["id"] == "f002")
        self.assertEqual(f002["annotations"][0]["comment"], "f002 | xss | reflected")


if __name__ == "__main__":
    unittest.main()
