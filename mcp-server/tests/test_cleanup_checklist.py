"""End-of-engagement cleanup reconciliation checklist.

The checklist must surface only actions that left persistent state on the target
(a created account, a dropped file, an opened listener) and stay quiet about
read-only recon. Reconciliation state must survive a reload — an operator checks
items off across several calls, not in one sitting.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from praetor import server
from praetor.tools.redteam import _cleanup, _oplog


def _tool(name):
    return server.mcp._tool_manager._tools[name].fn


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()


class TestCleanupChecklist(_Base):
    async def test_surfaces_only_state_changing_actions(self):
        # Read-only recon — must NOT appear.
        _oplog.record_action("box", "nmap", "nmap -sV 10.0.0.1", target="10.0.0.1")
        # Persistence: created a test account (net -> T1098) — must appear.
        _oplog.record_action("box", "net", "net user pentest_tmp P@ss /add",
                             target="DC01", description="created temp test account")

        result = await _tool("get_cleanup_checklist")("box")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["outstanding"], 1)
        item = result["items"][0]
        self.assertEqual(item["category"], "account")
        self.assertEqual(item["where"], "DC01")
        self.assertFalse(item["reconciled"])

    async def test_mark_reconciled_persists_across_reload(self):
        _oplog.record_action("box", "net", "net user pentest_tmp P@ss /add", target="DC01")
        item_id = (await _tool("get_cleanup_checklist")("box"))["items"][0]["item_id"]

        marked = await _tool("mark_cleanup_reconciled")("box", item_id, evidence="deleted on DC01")
        self.assertTrue(marked["reconciled"])
        self.assertEqual(marked["outstanding"], 0)

        # Fresh read (no in-memory state) — the flag survived the sidecar write.
        reloaded = _cleanup.build_checklist("box")["items"][0]
        self.assertTrue(reloaded["reconciled"])
        self.assertEqual(reloaded["evidence"], "deleted on DC01")

    async def test_mark_unknown_item_is_rejected(self):
        out = await _tool("mark_cleanup_reconciled")("box", "op9999")
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
