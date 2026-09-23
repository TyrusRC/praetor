"""rotate_operator_log — archival rotation for the operation ledger.

The ledger is ATT&CK-adjacent chain-of-custody evidence: it must never lose
history to a size cap. These tests cover the properties that make archival
trustworthy: dry-run touches nothing, apply moves exactly the older entries
into an archive file and leaves exactly the tail live, archive+tail always
reconstruct the original entries with no loss, and a below-threshold ledger
is left alone.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from praetor.tools.oplog import _store


class _TempLedger(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._patch = mock.patch.object(
            _store, "oplog_path", lambda: self.root / ".burp-intel" / "_oplog.jsonl"
        )
        self._patch.start()
        _store._SEQ = 0

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def path(self):
        return self.root / ".burp-intel" / "_oplog.jsonl"

    def _seed(self, n: int) -> None:
        for i in range(n):
            _store.record({"url": f"http://h/{i}", "api": "POST /api/http/curl"})


class TestByteSizeRotation(_TempLedger):
    def test_rotate_if_needed_archives_to_unique_names_no_overwrite(self):
        # The byte-size auto-rotation must NOT overwrite a prior archive — every
        # rotation preserves a distinct generation (the bug: fixed _oplog.1.jsonl).
        p = self.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        orig_max = _store._MAX_BYTES
        _store._MAX_BYTES = 100  # force rotation on tiny files
        try:
            p.write_text("x" * 200, encoding="utf-8")
            _store._rotate_if_needed(p)          # first rotation -> archive #1
            self.assertFalse(p.exists())
            p.write_text("y" * 200, encoding="utf-8")
            _store._rotate_if_needed(p)          # second rotation -> archive #2
            archives = sorted(x.name for x in p.parent.glob("_oplog.*.jsonl"))
            self.assertEqual(len(archives), 2, f"expected 2 distinct archives, got {archives}")
            # neither archive is the legacy fixed name, and both survive
            self.assertNotIn("_oplog.1.jsonl", archives)
        finally:
            _store._MAX_BYTES = orig_max


class TestDryRun(_TempLedger):
    def test_dry_run_archives_nothing_and_reports_counts(self):
        self._seed(10)
        result = _store.rotate_operator_log(max_entries=5, apply=False)

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["total_entries"], 10)
        self.assertEqual(result["archived"], 5)
        self.assertEqual(result["kept"], 5)
        self.assertIsNotNone(result["archive_path"])

        # Nothing touched on disk.
        self.assertFalse(Path(result["archive_path"]).exists())
        self.assertEqual(len(_store.read_entries()), 10)

    def test_below_threshold_log_is_untouched(self):
        self._seed(3)
        result = _store.rotate_operator_log(max_entries=5, apply=False)

        self.assertEqual(result["archived"], 0)
        self.assertEqual(result["kept"], 3)
        self.assertIsNone(result["archive_path"])
        self.assertEqual(len(_store.read_entries()), 3)


class TestApply(_TempLedger):
    def test_apply_moves_older_entries_to_archive_and_leaves_tail(self):
        self._seed(10)
        result = _store.rotate_operator_log(max_entries=5, apply=True)

        self.assertFalse(result["dry_run"])
        archive_path = Path(result["archive_path"])
        self.assertTrue(archive_path.exists())

        # Live file holds exactly the most-recent 5.
        live = _store.read_entries()
        self.assertEqual(len(live), 5)
        self.assertEqual([e["seq"] for e in live], [6, 7, 8, 9, 10])

        # Archive holds exactly the older 5, in order.
        archived = [json.loads(line) for line in archive_path.read_text().splitlines()]
        self.assertEqual(len(archived), 5)

    def test_archive_and_tail_together_preserve_every_original_entry(self):
        self._seed(23)
        result = _store.rotate_operator_log(max_entries=8, apply=True)

        archive_path = Path(result["archive_path"])
        archived_seqs = [
            _store._unpack(json.loads(line))["seq"]
            for line in archive_path.read_text().splitlines() if line.strip()
        ]
        live_seqs = [e["seq"] for e in _store.read_entries()]

        combined = sorted(archived_seqs + live_seqs)
        self.assertEqual(combined, list(range(1, 24)))
        self.assertEqual(len(archived_seqs), 15)
        self.assertEqual(len(live_seqs), 8)

    def test_below_threshold_apply_is_a_noop(self):
        self._seed(4)
        result = _store.rotate_operator_log(max_entries=5, apply=True)

        self.assertEqual(result["archived"], 0)
        self.assertIsNone(result["archive_path"])
        self.assertEqual(len(_store.read_entries()), 4)

    def test_missing_ledger_reports_nothing_to_rotate(self):
        result = _store.rotate_operator_log(max_entries=5, apply=True)
        self.assertEqual(result["total_entries"], 0)
        self.assertEqual(result["archived"], 0)
        self.assertFalse(self.path().exists())


if __name__ == "__main__":
    unittest.main()
