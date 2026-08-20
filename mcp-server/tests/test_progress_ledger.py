"""E2.1 — per-round progress ledger + deterministic stall detection."""
from __future__ import annotations

import shutil
import unittest

from praetor.tools.notes._helpers import _intel_dir, _sanitized
from praetor.tools.intel.checkpoint import (
    merge_checkpoint, load_checkpoint_data, stall_alert)


class ProgressLedgerTest(unittest.TestCase):
    DOMAIN = "e21-progress.test-throwaway.example"

    def tearDown(self):
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def test_no_progress_increments_and_progress_resets(self):
        merge_checkpoint(self.DOMAIN, progress={"progress_made": False,
                                                "stall_reason": "same 403s"})
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["progress"]["consecutive_no_progress"], 1)

        merge_checkpoint(self.DOMAIN, progress={"progress_made": False})
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["progress"]["consecutive_no_progress"], 2)
        self.assertIn("STALL", stall_alert(d))

        merge_checkpoint(self.DOMAIN, progress={"progress_made": True})
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["progress"]["consecutive_no_progress"], 0)
        self.assertEqual(stall_alert(d), "")

    def test_in_loop_flags_stall_immediately(self):
        merge_checkpoint(self.DOMAIN, progress={"progress_made": True,
                                                "in_loop": True})
        self.assertIn("STALL", stall_alert(load_checkpoint_data(self.DOMAIN)))

    def test_progress_does_not_disturb_tasks(self):
        merge_checkpoint(self.DOMAIN, tasks=[{"id": "T1", "title": "sqli",
                                              "status": "in_progress"}])
        merge_checkpoint(self.DOMAIN, progress={"progress_made": False})
        d = load_checkpoint_data(self.DOMAIN)
        self.assertEqual(d["tasks"][0]["title"], "sqli")
        self.assertEqual(d["progress"]["consecutive_no_progress"], 1)

    def test_no_progress_field_no_alert(self):
        merge_checkpoint(self.DOMAIN, phase="scan")
        self.assertEqual(stall_alert(load_checkpoint_data(self.DOMAIN)), "")


if __name__ == "__main__":
    unittest.main()
