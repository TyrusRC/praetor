from __future__ import annotations

import os
import unittest
from unittest import mock

from praetor.tools.mobile import _guards


class DenylistTest(unittest.TestCase):
    def test_factory_reset_refused(self):
        ok, why = _guards.check_command("shell am broadcast -a android.intent.action.MASTER_CLEAR")
        self.assertFalse(ok)
        self.assertIn("MASTER_CLEAR", why)

    def test_wipe_refused(self):
        ok, _ = _guards.check_command("shell recovery --wipe_data")
        self.assertFalse(ok)

    def test_pm_uninstall_refused(self):
        ok, why = _guards.check_command("shell pm uninstall com.other.app")
        self.assertFalse(ok)
        self.assertIn("uninstall", why)

    def test_pm_clear_refused(self):
        ok, _ = _guards.check_command("shell pm clear com.other.app")
        self.assertFalse(ok)

    def test_reboot_bootloader_refused(self):
        ok, _ = _guards.check_command("reboot bootloader")
        self.assertFalse(ok)

    def test_rm_rf_refused_via_shared_layer(self):
        ok, _ = _guards.check_command("shell rm -rf /sdcard/DCIM")
        self.assertFalse(ok)

    def test_send_sms_refused(self):
        ok, _ = _guards.check_command("shell service call isms 5 ...")
        self.assertFalse(ok)

    def test_benign_tap_allowed(self):
        ok, why = _guards.check_command("shell input tap 100 200")
        self.assertTrue(ok, why)

    def test_benign_screencap_allowed(self):
        ok, _ = _guards.check_command("exec-out screencap -p")
        self.assertTrue(ok)


class DeviceAllowlistTest(unittest.TestCase):
    def test_allowlisted_ok(self):
        with mock.patch.dict(os.environ, {"PRAETOR_MOBILE_DEVICES": "ABC123, UDID-9"}):
            self.assertEqual(_guards.allowed_devices(), ["ABC123", "UDID-9"])
            ok, _ = _guards.check_device("ABC123", connected_count=3)
            self.assertTrue(ok)

    def test_not_allowlisted_refused(self):
        with mock.patch.dict(os.environ, {"PRAETOR_MOBILE_DEVICES": "ABC123"}):
            ok, why = _guards.check_device("ZZZ999", connected_count=2)
            self.assertFalse(ok)
            self.assertIn("allowlist", why)

    def test_empty_allowlist_single_device_ok(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, _ = _guards.check_device("ABC123", connected_count=1)
            self.assertTrue(ok)

    def test_empty_allowlist_multiple_devices_refused(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, why = _guards.check_device("ABC123", connected_count=2)
            self.assertFalse(ok)
            self.assertIn("allowlist", why)

    def test_strict_refuses_without_allowlist(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ok, _ = _guards.check_device("ABC123", connected_count=1, strict=True)
            self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
