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


class SettingDenylistTest(unittest.TestCase):
    def test_locksettings_clear_refused(self):
        ok, why = _guards.check_command("shell locksettings clear")
        self.assertFalse(ok)
        self.assertIn("locksettings", why)

    def test_locksettings_set_disabled_refused(self):
        ok, _ = _guards.check_command("shell locksettings set-disabled true")
        self.assertFalse(ok)

    def test_locksettings_set_pin_refused(self):
        ok, _ = _guards.check_command("shell locksettings set-pin 0000")
        self.assertFalse(ok)

    def test_lockscreen_disabled_refused(self):
        ok, _ = _guards.check_command("shell settings put secure lockscreen.disabled 1")
        self.assertFalse(ok)

    def test_package_verifier_enable_refused(self):
        ok, _ = _guards.check_command("shell settings put global package_verifier_enable 0")
        self.assertFalse(ok)

    def test_verifier_verify_adb_installs_refused(self):
        ok, _ = _guards.check_command("shell settings put global verifier_verify_adb_installs 0")
        self.assertFalse(ok)

    def test_upload_apk_enable_refused(self):
        ok, _ = _guards.check_command("shell settings put global upload_apk_enable 0")
        self.assertFalse(ok)

    def test_package_verifier_user_consent_refused(self):
        ok, why = _guards.check_command("shell settings put global package_verifier_user_consent 0")
        self.assertFalse(ok)
        self.assertIn("package_verifier", why)

    def test_package_verifier_state_refused(self):
        ok, _ = _guards.check_command("shell settings put global package_verifier_state 0")
        self.assertFalse(ok)

    def test_package_verifier_secure_scope_refused(self):
        ok, _ = _guards.check_command("shell settings put secure package_verifier_user_consent 0")
        self.assertFalse(ok)

    def test_install_non_market_apps_secure_refused(self):
        ok, _ = _guards.check_command("shell settings put secure install_non_market_apps 1")
        self.assertFalse(ok)

    def test_install_non_market_apps_global_refused(self):
        ok, _ = _guards.check_command("shell settings put global install_non_market_apps 1")
        self.assertFalse(ok)

    def test_user_setup_complete_refused(self):
        ok, _ = _guards.check_command("shell settings put secure user_setup_complete 0")
        self.assertFalse(ok)

    def test_settings_get_http_proxy_allowed(self):
        ok, why = _guards.check_command("shell settings get global http_proxy")
        self.assertTrue(ok, why)

    def test_settings_put_brightness_allowed(self):
        ok, why = _guards.check_command("shell settings put system screen_brightness 120")
        self.assertTrue(ok, why)

    def test_settings_put_http_proxy_allowed(self):
        ok, why = _guards.check_command("shell settings put global http_proxy 127.0.0.1:8080")
        self.assertTrue(ok, why)

    def test_settings_get_android_id_allowed(self):
        ok, why = _guards.check_command("shell settings get secure android_id")
        self.assertTrue(ok, why)

    def test_settings_get_package_verifier_enable_allowed(self):
        ok, why = _guards.check_command("shell settings get global package_verifier_enable")
        self.assertTrue(ok, why)


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
