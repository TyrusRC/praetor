from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from praetor.tools.mobile import _store


class StoreTest(unittest.TestCase):
    def test_log_action_returns_oplog_id(self):
        with mock.patch.object(_store, "record_action", return_value="op0007") as ra:
            oid = _store.log_action("ex.com", "ABC123", "shell input tap 1 2",
                                    description="tap", rc=0)
        self.assertEqual(oid, "op0007")
        # command + target carried through to the oplog
        _, kwargs = ra.call_args
        self.assertEqual(kwargs["target"], "ABC123")
        self.assertEqual(kwargs["returncode"], 0)

    def test_log_loot_records_path(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "prefs.xml"
            f.write_text("<map/>")
            with mock.patch.object(_store, "record_loot", return_value={"id": "loot0001"}) as rl:
                row = _store.log_loot("ex.com", "shared_prefs", str(f), "ABC123", oplog_id="op1")
        self.assertEqual(row["id"], "loot0001")
        _, kwargs = rl.call_args
        self.assertTrue(kwargs["is_path"])

    def test_artifact_dir_created(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(_store, "ensure_workspace",
                                   return_value={"root": Path(td)}):
                d = _store.artifact_dir("ex.com")
                self.assertTrue(d.exists())
                self.assertTrue(str(d).endswith("artifacts/mobile"))


if __name__ == "__main__":
    unittest.main()
