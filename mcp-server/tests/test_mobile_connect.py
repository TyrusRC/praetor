# tests/test_mobile_connect.py
from __future__ import annotations

import unittest
from unittest import mock

from praetor.tools.mobile import connect, _device


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco
    return _Stub(), captured


class MobileConnectTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        connect.register(self.stub)
        self.dev = _device.Device(id="USB123", platform="android", authorized=True)

    async def test_tcpip_resolves_usb_device(self):
        with mock.patch.object(connect, "resolve_device", return_value=self.dev), \
             mock.patch.object(connect, "_run_cmd",
                               return_value=("restarting in TCP mode port: 5555", "", 0)) as rc, \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="tcpip")
        rc.assert_called_once_with(["adb", "-s", "USB123", "tcpip", "5555"], bypass_proxy=True)
        self.assertEqual(out["action"], "tcpip")
        self.assertEqual(out["port"], 5555)
        self.assertEqual(out["oplog_id"], "op1")
        self.assertEqual(out["output"], "restarting in TCP mode port: 5555")
        self.assertIn("note", out)

    async def test_connect_success_returns_serial(self):
        with mock.patch.object(connect, "_run_cmd",
                               return_value=("connected to 1.2.3.4:5555", "", 0)) as rc, \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="connect", ip="1.2.3.4")
        rc.assert_called_once_with(["adb", "connect", "1.2.3.4:5555"], bypass_proxy=True)
        self.assertEqual(out["serial"], "1.2.3.4:5555")
        self.assertNotIn("error", out)

    async def test_connect_failure_is_error(self):
        with mock.patch.object(connect, "_run_cmd",
                               return_value=("failed to connect to 1.2.3.4:5555", "", 1)), \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="connect", ip="1.2.3.4")
        self.assertIn("error", out)

    async def test_connect_requires_ip(self):
        out = await self.cap["mobile_connect"](action="connect")
        self.assertIn("error", out)

    async def test_pair_sends_code_to_pair_port(self):
        with mock.patch.object(connect, "_run_cmd",
                               return_value=("Successfully paired", "", 0)) as rc, \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="pair", ip="1.2.3.4",
                                                    port=37000, code="123456")
        rc.assert_called_once_with(["adb", "pair", "1.2.3.4:37000", "123456"], bypass_proxy=True)
        self.assertNotIn("error", out)

    async def test_pair_requires_ip_and_code(self):
        out = await self.cap["mobile_connect"](action="pair", ip="1.2.3.4")
        self.assertIn("error", out)

    async def test_disconnect_with_ip(self):
        with mock.patch.object(connect, "_run_cmd", return_value=("disconnected", "", 0)) as rc, \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="disconnect", ip="1.2.3.4")
        rc.assert_called_once_with(["adb", "disconnect", "1.2.3.4:5555"], bypass_proxy=True)
        self.assertNotIn("error", out)

    async def test_disconnect_without_ip(self):
        with mock.patch.object(connect, "_run_cmd", return_value=("disconnected everything", "", 0)) as rc, \
             mock.patch.object(connect, "log_action", return_value="op1"):
            out = await self.cap["mobile_connect"](action="disconnect")
        rc.assert_called_once_with(["adb", "disconnect"], bypass_proxy=True)

    async def test_list_returns_device_summary(self):
        with mock.patch.object(connect, "list_devices", return_value=[self.dev]):
            out = await self.cap["mobile_connect"](action="list")
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["devices"][0]["id"], "USB123")

    async def test_unknown_action_is_error(self):
        out = await self.cap["mobile_connect"](action="bogus")
        self.assertIn("error", out)
        self.assertIn("tcpip|connect|pair|disconnect|list", out["error"])


if __name__ == "__main__":
    unittest.main()
