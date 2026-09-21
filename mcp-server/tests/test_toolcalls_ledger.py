"""Universal tool-call ledger (oplog/_toolcalls.py) — secret-free, fail-open."""

import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools.oplog import _toolcalls as T


class MakeEntryTest(unittest.TestCase):
    def test_entry_is_secret_free(self):
        e = T.make_entry("curl_request", True, 12.34)
        # only these keys — never argument values or result bodies
        self.assertEqual(set(e), {"ts", "tool", "ok", "elapsed_ms"})
        self.assertEqual(e["tool"], "curl_request")
        self.assertEqual(e["elapsed_ms"], 12.3)

    def test_error_truncated(self):
        e = T.make_entry("x", False, 1.0, error="boom " * 100)
        self.assertFalse(e["ok"])
        self.assertLessEqual(len(e["error"]), 200)


class RecordReadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        os.environ.pop("PRAETOR_TOOLLOG", None)

    def tearDown(self):
        os.chdir(self._cwd)
        os.environ.pop("PRAETOR_TOOLLOG", None)

    def test_round_trip_and_filters(self):
        T.record("auto_probe", True, 5.0)
        T.record("save_finding", False, 9.0, error="ValueError: bad")
        T.record("auto_probe", True, 7.0)

        allrows = T.read(limit=50)
        self.assertEqual(len(allrows), 3)
        self.assertEqual(allrows[0]["tool"], "auto_probe")   # newest first

        self.assertEqual(len(T.read(tool="auto_probe")), 2)
        errs = T.read(errors_only=True)
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0]["tool"], "save_finding")

        # persisted as JSONL under .burp-intel/_harness/
        ledger = Path(self.tmp) / ".burp-intel" / "_harness" / "toolcalls.jsonl"
        self.assertTrue(ledger.exists())
        self.assertEqual(len(ledger.read_text().splitlines()), 3)

    def test_disabled_writes_nothing(self):
        os.environ["PRAETOR_TOOLLOG"] = "off"
        T.record("auto_probe", True, 5.0)
        self.assertEqual(T.read(), [])
        self.assertFalse((Path(self.tmp) / ".burp-intel" / "_harness" / "toolcalls.jsonl").exists())

    def test_read_missing_ledger_is_empty(self):
        self.assertEqual(T.read(), [])


if __name__ == "__main__":
    unittest.main()
