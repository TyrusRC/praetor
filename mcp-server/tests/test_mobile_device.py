from __future__ import annotations

import os
import unittest
from unittest import mock

from praetor.tools.mobile import _device


_ADB_DEVICES = (
    "List of devices attached\n"
    "ABC123   device product:foo model:Pixel_7 device:panther transport_id:1\n"
    "emulator-5554   offline\n"
)
_IDB_TARGETS = '[{"udid": "UDID-9", "name": "iPhone 15", "os_version": "17.4", "state": "Booted"}]'


class ListDevicesTest(unittest.IsolatedAsyncioTestCase):
    async def test_merges_android_and_ios(self):
        async def fake_run(cmd, timeout=120, bypass_proxy=False, **kw):
            if cmd[0] == "adb":
                return _ADB_DEVICES, "", 0
            if cmd[0] == "idb":
                return _IDB_TARGETS, "", 0
            return "", "", 1

        with mock.patch.object(_device, "_run_cmd", fake_run), \
             mock.patch.object(_device, "_check_tool", lambda n: True):
            devs = await _device.list_devices()
        ids = {d.id: d for d in devs}
        self.assertIn("ABC123", ids)
        self.assertEqual(ids["ABC123"].platform, "android")
        self.assertTrue(ids["ABC123"].authorized)
        self.assertFalse(ids["emulator-5554"].authorized)  # offline
        self.assertIn("UDID-9", ids)
        self.assertEqual(ids["UDID-9"].platform, "ios")

    async def test_missing_tools_degrade(self):
        with mock.patch.object(_device, "_check_tool", lambda n: False):
            devs = await _device.list_devices()
        self.assertEqual(devs, [])


class ResolveDeviceTest(unittest.IsolatedAsyncioTestCase):
    async def _patch(self, devices):
        async def fake_list():
            return devices
        return mock.patch.object(_device, "list_devices", fake_list)

    async def test_explicit_id_allowlisted(self):
        d = _device.Device(id="ABC123", platform="android", authorized=True)
        with await self._patch([d]), mock.patch.dict(os.environ, {"PRAETOR_MOBILE_DEVICES": "ABC123"}):
            got = await _device.resolve_device("ABC123")
        self.assertEqual(got.id, "ABC123")

    async def test_unknown_id_raises(self):
        d = _device.Device(id="ABC123", platform="android", authorized=True)
        with await self._patch([d]):
            with self.assertRaises(_device.DeviceError):
                await _device.resolve_device("NOPE")

    async def test_not_allowlisted_raises(self):
        d = _device.Device(id="ABC123", platform="android", authorized=True)
        d2 = _device.Device(id="DEF456", platform="android", authorized=True)
        with await self._patch([d, d2]), mock.patch.dict(os.environ, {"PRAETOR_MOBILE_DEVICES": "ABC123"}):
            with self.assertRaises(_device.DeviceError):
                await _device.resolve_device("DEF456")

    async def test_single_device_autoselect(self):
        d = _device.Device(id="ABC123", platform="android", authorized=True)
        with await self._patch([d]), mock.patch.dict(os.environ, {}, clear=True):
            got = await _device.resolve_device()
        self.assertEqual(got.id, "ABC123")


class BackendForTest(unittest.TestCase):
    def test_android(self):
        b = _device.backend_for(_device.Device(id="X", platform="android"))
        self.assertIsInstance(b, _device.AndroidBackend)

    def test_ios(self):
        b = _device.backend_for(_device.Device(id="X", platform="ios"))
        self.assertIsInstance(b, _device.IOSBackend)


if __name__ == "__main__":
    unittest.main()
