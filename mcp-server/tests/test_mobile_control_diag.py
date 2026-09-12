# tests/test_mobile_control_diag.py
from __future__ import annotations

import unittest
from unittest import mock

from praetor.tools.mobile import control, _device


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco
    return _Stub(), captured


class DiagToolTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        control.register(self.stub)
        self.dev = _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_logcat_ok(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "logs", return_value="line1\nline2"), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_logcat"](domain="ex.com", lines=2)
        self.assertIn("line1", out["logs"])

    async def test_shell_destructive_refused(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev):
            out = await self.cap["mobile_shell"](command="rm -rf /sdcard", domain="ex.com")
        self.assertIn("error", out)

    async def test_shell_benign_ok(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "shell", return_value=("uid=0", "", 0)), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_shell"](command="id", domain="ex.com")
        self.assertEqual(out["rc"], 0)

    async def test_pull_records_loot(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "pull", return_value=None), \
             mock.patch.object(control, "artifact_dir") as ad, \
             mock.patch.object(control, "log_action", return_value="op1"), \
             mock.patch.object(control, "log_loot", return_value={"id": "loot1"}) as ll:
            ad.return_value.__truediv__ = lambda self, other: __import__("pathlib").Path("/tmp") / other
            out = await self.cap["mobile_pull_file"](remote="/data/data/com.x/shared_prefs/p.xml",
                                                     domain="ex.com")
        self.assertEqual(out["loot"]["id"], "loot1")
        ll.assert_called_once()


if __name__ == "__main__":
    unittest.main()
