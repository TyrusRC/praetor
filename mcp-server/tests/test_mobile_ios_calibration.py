"""Real-device calibration fix tests (iOS 16.7.12, go-ios, jailbroken):

- `ios list --json` is invalid in this go-ios version (usage message on
  stderr, empty stdout) -- list_devices must call plain `ios list`.
- `ios screenshot` fails until the Developer Disk Image is mounted --
  screenshot must retry once via `_mount_ddi` before falling back.

Fixture bundle ids are placeholders only (`com.example.*`) -- never a real
app bundle id captured from the device.
"""
from __future__ import annotations

import unittest
from unittest import mock

from praetor.tools.mobile import _device
from praetor.tools.mobile._device import Device, DeviceError, IOSBackend, _parse_ios_list


class ListDevicesUsesPlainIosListTest(unittest.IsolatedAsyncioTestCase):
    async def test_no_json_flag(self):
        seen_cmds = []

        async def fake_run(cmd, timeout=120, bypass_proxy=False, **kw):
            seen_cmds.append(cmd)
            if cmd[0] == "ios":
                return '{"deviceList":["UDID-X"]}', "", 0
            return "", "", 1

        with mock.patch.object(_device, "_run_cmd", fake_run), \
             mock.patch.object(_device, "_check_tool", lambda n: n == "ios"):
            devs = await _device.list_devices()

        ios_cmds = [c for c in seen_cmds if c[0] == "ios"]
        self.assertEqual(len(ios_cmds), 1)
        self.assertEqual(ios_cmds[0], ["ios", "list"])
        self.assertNotIn("--json", ios_cmds[0])
        self.assertEqual([d.id for d in devs], ["UDID-X"])
        self.assertEqual(devs[0].platform, "ios")


class ParseIosListRegressionTest(unittest.TestCase):
    def test_two_devices(self):
        devs = _parse_ios_list('{"deviceList":["a","b"]}')
        self.assertEqual([d.id for d in devs], ["a", "b"])
        self.assertTrue(all(d.platform == "ios" for d in devs))

    def test_null_device_list(self):
        self.assertEqual(_parse_ios_list('{"deviceList": null}'), [])

    def test_top_level_null(self):
        self.assertEqual(_parse_ios_list("null"), [])


class IosScreenshotDdiMountRetryTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-EXAMPLE", platform="ios")
        self.backend = IOSBackend()

    async def test_mounts_ddi_and_retries_on_first_failure(self):
        calls = []

        async def fake_ios(self_backend, dev, args, timeout=60):
            calls.append(list(args))
            if args[0] == "screenshot":
                screenshot_calls_so_far = sum(1 for c in calls if c[0] == "screenshot")
                if screenshot_calls_so_far == 1:
                    return "", "Could not start screenshotr service", 1
                return "", "", 0
            if args[0] == "image":
                return "", "", 0  # DDI mount succeeds
            return "", "", 1

        with mock.patch.object(_device, "_check_tool", lambda n: n == "ios"), \
             mock.patch.object(IOSBackend, "_ios", fake_ios):
            await self.backend.screenshot(self.dev, "/tmp/out.png")

        screenshot_calls = [c for c in calls if c[0] == "screenshot"]
        mount_calls = [c for c in calls if c[0] == "image"]
        self.assertEqual(len(screenshot_calls), 2)
        self.assertEqual(len(mount_calls), 1)

    async def test_all_tools_fail_raises_ddi_error(self):
        async def fake_ios(self_backend, dev, args, timeout=60):
            return "", "fail", 1

        with mock.patch.object(_device, "_check_tool", lambda n: n == "ios"), \
             mock.patch.object(IOSBackend, "_ios", fake_ios):
            with self.assertRaises(DeviceError) as ctx:
                await self.backend.screenshot(self.dev, "/tmp/out.png")
        self.assertIn("Developer Disk Image", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
