"""Tests for the go-ios/libimobiledevice IOSBackend (Task 4) — parsers +
per-method tool-priority dispatch. No real device; all subprocess calls
(_run_cmd) and tool presence (_check_tool) are mocked."""
from __future__ import annotations

import unittest
from unittest import mock

from praetor.tools.mobile import _device, _wda
from praetor.tools.mobile._device import (
    Device,
    DeviceError,
    IOSBackend,
    _parse_ideviceinfo,
    _parse_ideviceinstaller_list,
    _parse_idb_apps,
    _parse_ios_apps,
    _parse_ios_info,
    _parse_ios_list,
)


# --- Parser tests ------------------------------------------------------

class ParseIosListTest(unittest.TestCase):
    def test_device_list_json_shape(self):
        devs = _parse_ios_list('{"deviceList": ["UDID-1", "UDID-2"]}')
        self.assertEqual([d.id for d in devs], ["UDID-1", "UDID-2"])
        self.assertTrue(all(d.platform == "ios" for d in devs))

    def test_bare_json_array(self):
        devs = _parse_ios_list('["UDID-1"]')
        self.assertEqual([d.id for d in devs], ["UDID-1"])

    def test_dict_entries_with_metadata(self):
        devs = _parse_ios_list('{"deviceList": [{"udid": "UDID-1", "name": "iPhone 15", "os_version": "17.4"}]}')
        self.assertEqual(devs[0].id, "UDID-1")
        self.assertEqual(devs[0].model, "iPhone 15")
        self.assertEqual(devs[0].os_version, "17.4")

    def test_non_json_falls_back_to_line_list(self):
        devs = _parse_ios_list("UDID-1\nUDID-2\n")
        self.assertEqual([d.id for d in devs], ["UDID-1", "UDID-2"])

    def test_empty_input(self):
        self.assertEqual(_parse_ios_list(""), [])

    def test_device_list_null_no_device_attached(self):
        # Go marshals a nil slice as JSON null -- the common no-device case.
        self.assertEqual(_parse_ios_list('{"deviceList": null}'), [])

    def test_top_level_null(self):
        self.assertEqual(_parse_ios_list("null"), [])


class ParseIosInfoTest(unittest.TestCase):
    def test_json_object(self):
        info = _parse_ios_info('{"DeviceName": "iPhone", "ProductVersion": "17.4"}')
        self.assertEqual(info["DeviceName"], "iPhone")

    def test_key_value_lines_fallback(self):
        info = _parse_ios_info("DeviceName: iPhone\nProductVersion: 17.4\n")
        self.assertEqual(info["ProductVersion"], "17.4")

    def test_ideviceinfo_parser_directly(self):
        info = _parse_ideviceinfo("ProductType: iPhone14,5\nDeviceName: Bob's iPhone\n")
        self.assertEqual(info["ProductType"], "iPhone14,5")


class ParseAppListsTest(unittest.TestCase):
    def test_ios_apps_third_party_filter(self):
        raw = ('[{"CFBundleIdentifier": "com.apple.mobilesafari", "ApplicationType": "System"},'
              '{"CFBundleIdentifier": "com.example.app", "ApplicationType": "User"}]')
        self.assertEqual(_parse_ios_apps(raw, third_party_only=True), ["com.example.app"])
        self.assertEqual(_parse_ios_apps(raw, third_party_only=False),
                         ["com.apple.mobilesafari", "com.example.app"])

    def test_ideviceinstaller_list(self):
        raw = 'Total: 1 apps\ncom.example.app - "Example" 1.0\n'
        self.assertEqual(_parse_ideviceinstaller_list(raw), ["com.example.app"])

    def test_idb_apps_json_lines(self):
        raw = '{"bundle_id": "com.example.app", "install_type": "user"}\n'
        self.assertEqual(_parse_idb_apps(raw, third_party_only=True), ["com.example.app"])

    def test_ios_apps_null_no_apps(self):
        # Go marshals a nil slice as JSON null.
        self.assertEqual(_parse_ios_apps("null", third_party_only=True), [])

    def test_ios_apps_empty_array(self):
        self.assertEqual(_parse_ios_apps("[]", third_party_only=True), [])


# --- IOSBackend method dispatch tests -----------------------------------

def _tool_gate(present: set[str]):
    return lambda name: name in present


class IosBackendScreenshotTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_prefers_go_ios(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "ios")
            self.assertIn("screenshot", cmd)
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios", "idb", "idevicescreenshot"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.screenshot(self.dev, "/tmp/out.png")

    async def test_falls_back_to_idevicescreenshot_without_go_ios(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "idevicescreenshot")
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idevicescreenshot", "idb"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.screenshot(self.dev, "/tmp/out.png")

    async def test_falls_back_to_idb_when_only_idb_present(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "idb")
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idb"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.screenshot(self.dev, "/tmp/out.png")

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.screenshot(self.dev, "/tmp/out.png")

    async def test_go_ios_failure_raises(self):
        async def fake_run(cmd, **kw):
            return "", "boom", 1
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            with self.assertRaises(DeviceError):
                await self.backend.screenshot(self.dev, "/tmp/out.png")


class IosBackendDeviceInfoTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios", model="iPhone 15", os_version="17.4")
        self.backend = IOSBackend()

    async def test_go_ios_enriches(self):
        async def fake_run(cmd, **kw):
            return '{"DeviceName": "Real Name", "ProductVersion": "17.5"}', "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            info = await self.backend.device_info(self.dev)
        self.assertEqual(info["model"], "Real Name")
        self.assertEqual(info["os_version"], "17.5")

    async def test_no_tool_falls_back_to_cached_discovery_fields(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            info = await self.backend.device_info(self.dev)
        self.assertEqual(info["model"], "iPhone 15")
        self.assertEqual(info["os_version"], "17.4")
        self.assertIsNone(info["rooted_hint"])

    async def test_never_raises_on_tool_failure(self):
        async def fake_run(cmd, **kw):
            return "", "err", 1
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            info = await self.backend.device_info(self.dev)
        self.assertEqual(info["model"], "iPhone 15")


class IosBackendAppListTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_go_ios_path(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:2], ["ios", "apps"])
            return '[{"CFBundleIdentifier": "com.example.app", "ApplicationType": "User"}]', "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            pkgs = await self.backend.app_list(self.dev, third_party_only=True)
        self.assertEqual(pkgs, ["com.example.app"])

    async def test_ideviceinstaller_fallback(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "ideviceinstaller")
            return 'com.example.app - "Example" 1.0\n', "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ideviceinstaller"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            pkgs = await self.backend.app_list(self.dev, third_party_only=True)
        self.assertEqual(pkgs, ["com.example.app"])

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.app_list(self.dev, third_party_only=True)


class IosBackendAppControlTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_go_ios_launch(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:2], ["ios", "launch"])
            self.assertIn("com.example.app", cmd)
            return "launched", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            out = await self.backend.app_control(self.dev, "start", "com.example.app")
        self.assertEqual(out, "launched")

    async def test_go_ios_kill(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:2], ["ios", "kill"])
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.app_control(self.dev, "stop", "com.example.app")

    async def test_idb_fallback(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "idb")
            self.assertIn("launch", cmd)
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idb"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.app_control(self.dev, "start", "com.example.app")

    async def test_unknown_action_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})):
            with self.assertRaises(DeviceError):
                await self.backend.app_control(self.dev, "clear", "com.example.app")

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.app_control(self.dev, "start", "com.example.app")


class IosBackendDeeplinkTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_prefers_idb_open(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "idb")
            self.assertIn("open", cmd)
            return "opened", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idb", "ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            out = await self.backend.deeplink(self.dev, "myapp://x", "")
        self.assertEqual(out, "opened")

    async def test_go_ios_needs_package(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})):
            with self.assertRaises(DeviceError):
                await self.backend.deeplink(self.dev, "myapp://x", "")

    async def test_go_ios_launches_by_package(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:2], ["ios", "launch"])
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.deeplink(self.dev, "myapp://x", "com.example.app")

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.deeplink(self.dev, "myapp://x", "")


class IosBackendLogsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_go_ios_bounded_syslog(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:3], ["timeout", "8", "ios"])
            self.assertIn("syslog", cmd)
            return "line1\nline2\nline3\n", "", 124  # coreutils timeout kill
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            out = await self.backend.logs(self.dev, "", lines=2)
        self.assertEqual(out, "line2\nline3")

    async def test_idevicesyslog_fallback(self):
        async def fake_run(cmd, **kw):
            self.assertIn("idevicesyslog", cmd)
            return "a\nb\n", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idevicesyslog"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            out = await self.backend.logs(self.dev, "", lines=0)
        self.assertEqual(out, "a\nb")

    async def test_filter_expr_substring_matches(self):
        async def fake_run(cmd, **kw):
            return "keep me\nskip\nkeep too\n", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idevicesyslog"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            out = await self.backend.logs(self.dev, "keep", lines=0)
        self.assertEqual(out, "keep me\nkeep too")

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.logs(self.dev, "", lines=10)


class IosBackendPullTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_requires_package(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})):
            with self.assertRaises(DeviceError):
                await self.backend.pull(self.dev, "/Documents/x.db", "/tmp/x.db", package="")

    async def test_go_ios_afc_pull(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[:2], ["ios", "afc"])
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"ios"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.pull(self.dev, "/Documents/x.db", "/tmp/x.db", package="com.example.app")

    async def test_idb_fallback(self):
        async def fake_run(cmd, **kw):
            self.assertEqual(cmd[0], "idb")
            return "", "", 0
        with mock.patch.object(_device, "_check_tool", _tool_gate({"idb"})), \
             mock.patch.object(_device, "_run_cmd", fake_run):
            await self.backend.pull(self.dev, "/Documents/x.db", "/tmp/x.db", package="com.example.app")

    async def test_no_tool_raises(self):
        with mock.patch.object(_device, "_check_tool", _tool_gate(set())):
            with self.assertRaises(DeviceError):
                await self.backend.pull(self.dev, "/Documents/x.db", "/tmp/x.db", package="com.example.app")


class IosBackendUiStubTest(unittest.IsolatedAsyncioTestCase):
    """tap/swipe/input_text/key/ui_dump_raw are Task 5 (WebDriverAgent) — the
    go-ios tool name change makes the old idb-flavored argv wrong, so these
    must refuse loudly rather than send bad commands."""

    async def test_ui_methods_raise_pointing_at_wda(self):
        backend = IOSBackend()
        dev = Device(id="UDID-1", platform="ios")
        # FINDING 5: mock the tool-presence check directly -- on a box WITH
        # go-ios installed, an unmocked check would let ensure_session spawn
        # real runwda/forward subprocesses and block ~15s per assertion below.
        with mock.patch.object(_wda, "_check_tool", lambda n: False):
            with self.assertRaises(DeviceError):
                await backend.ui_dump_raw(dev)
            with self.assertRaises(DeviceError):
                await backend.tap(dev, 1, 2)
            with self.assertRaises(DeviceError):
                await backend.swipe(dev, 1, 2, 3, 4, 100)
            with self.assertRaises(DeviceError):
                await backend.input_text(dev, "hi")
            with self.assertRaises(DeviceError):
                await backend.key(dev, "HOME")


class IosBackendShellTest(unittest.IsolatedAsyncioTestCase):
    async def test_shell_unsupported(self):
        backend = IOSBackend()
        dev = Device(id="UDID-1", platform="ios")
        with self.assertRaises(DeviceError):
            await backend.shell(dev, "id")


class BackendBinaryNameTest(unittest.TestCase):
    def test_canonical_tool_is_ios_not_go_ios(self):
        self.assertEqual(IOSBackend.tool, "ios")


if __name__ == "__main__":
    unittest.main()
