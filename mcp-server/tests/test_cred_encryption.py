"""Credential store encrypts secrets at rest; plaintext never hits disk."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from praetor.tools.redteam import _creds


class CredEncryptionTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="creds-"))
        net = self.tmp / "network"
        net.mkdir(parents=True)
        # Point the store at the temp workspace.
        self.patcher = mock.patch.object(
            _creds, "ensure_workspace", return_value={"network": net})
        self.patcher.start()
        self.net = net
        os.environ.pop("PRAETOR_CRED_KEY", None)   # force sidecar-key path

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plaintext_never_on_disk(self):
        secret = "SuperSecret_Passw0rd!"
        row = _creds.record_credential("d", "admin", secret, realm="CORP")
        raw = (self.net / "credentials.json").read_text()
        self.assertNotIn(secret, raw)               # not plaintext in the json
        self.assertIn("secret_enc", raw)            # ciphertext stored instead
        self.assertNotIn(secret, json.dumps(row))   # returned row is redacted
        self.assertIn("key_note", row)              # operator told where the key is
        self.assertTrue((self.net / "credentials.key").exists())

    def test_get_secret_decrypts_for_reuse(self):
        secret = "hunter2hunter2"
        rec = _creds.record_credential("d", "svc", secret)
        got = _creds.get_secret("d", rec["_id"])
        self.assertEqual(got["secret"], secret)     # reuse path recovers plaintext

    def test_list_is_redacted(self):
        _creds.record_credential("d", "u", "AKIAABCDEFGHIJKLMNOP")
        listed = _creds.list_credentials("d")
        self.assertEqual(len(listed), 1)
        self.assertNotIn("secret_enc", listed[0])
        self.assertNotEqual(listed[0]["secret"], "AKIAABCDEFGHIJKLMNOP")
        self.assertIn("…", listed[0]["secret"])

    def test_dedup_on_fingerprint(self):
        _creds.record_credential("d", "u", "same-pass", realm="R", valid_on=["h1"])
        r2 = _creds.record_credential("d", "u", "same-pass", realm="R", valid_on=["h2"])
        self.assertTrue(r2["merged"])
        self.assertEqual(len(_creds.list_credentials("d")), 1)
        self.assertIn("h1", r2["valid_on"])
        self.assertIn("h2", r2["valid_on"])

    def test_env_key_roundtrip(self):
        os.environ["PRAETOR_CRED_KEY"] = "operator-passphrase"
        try:
            rec = _creds.record_credential("d", "u", "envkeypass")
            self.assertIn("PRAETOR_CRED_KEY", rec["key_note"])
            self.assertEqual(_creds.get_secret("d", rec["_id"])["secret"], "envkeypass")
        finally:
            os.environ.pop("PRAETOR_CRED_KEY", None)


if __name__ == "__main__":
    unittest.main()
