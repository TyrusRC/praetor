"""Post-ex: credential store + offline hash cracking (the OSEP reuse loop)."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.redteam import _creds


def _tool(n):
    return server.mcp._tool_manager._tools[n].fn


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


class TestCredentialStore(_Base):
    async def test_record_and_redact(self):
        out = await _tool("record_credential")("box", "svc_sql", "SuperSecret123!",
                                                realm="CORP", source="secretsdump")
        self.assertIn("cred001", out)
        self.assertNotIn("SuperSecret123!", out)   # redacted in transcript
        # full secret kept usable on disk
        self.assertEqual(_creds.get_secret("box", "cred001")["secret"], "SuperSecret123!")

    async def test_dedupe_merges_hosts(self):
        await _tool("record_credential")("box", "u", "p", realm="CORP", valid_on="10.0.0.1")
        await _tool("record_credential")("box", "u", "p", realm="CORP", valid_on="10.0.0.2")
        creds = _creds.list_credentials("box", "CORP")
        self.assertEqual(len(creds), 1)
        self.assertEqual(set(creds[0]["valid_on"]), {"10.0.0.1", "10.0.0.2"})

    async def test_list_redacts(self):
        await _tool("record_credential")("box", "admin", "Password1", secret_type="ntlm")
        out = await _tool("list_credentials")("box")
        self.assertIn("admin", out)
        self.assertNotIn("Password1", out)


class TestCrackHashes(_Base):
    async def test_unknown_hash_type(self):
        out = await _tool("crack_hashes")("box", "not-a-type", hashes="abc")
        self.assertIn("Unknown hash_type", out)

    def _wordlist(self) -> str:
        wl = self.root / "wl.txt"
        wl.write_text("Autumn2024!\n")
        return str(wl)

    async def test_crack_records_credentials(self):
        # hashcat --show returns hash:password; an AS-REP username is embedded.
        asrep = "$krb5asrep$23$jdoe@CORP.LOCAL:aabbcc...ddeeff"
        show_out = f"{asrep}:Autumn2024!"
        with patch("burpsuite_mcp.tools.redteam.postex._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.redteam.postex._run_cmd",
                   new=AsyncMock(return_value=(show_out, "", 0))):
            out = await _tool("crack_hashes")("box", "asrep", hashes=asrep,
                                              wordlist=self._wordlist())
        self.assertIn("1/1 cracked", out)
        self.assertIn("jdoe", out)
        self.assertNotIn("Autumn2024!", out)       # redacted
        creds = _creds.list_credentials("box")
        self.assertEqual(len(creds), 1)
        self.assertEqual(_creds.get_secret("box", creds[0]["id"])["secret"], "Autumn2024!")

    async def test_no_cracks_is_clean(self):
        with patch("burpsuite_mcp.tools.redteam.postex._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.redteam.postex._run_cmd",
                   new=AsyncMock(return_value=("", "", 0))):
            out = await _tool("crack_hashes")("box", "ntlm", hashes="deadbeef" * 4,
                                              wordlist=self._wordlist())
        self.assertIn("0/1", out)


if __name__ == "__main__":
    unittest.main()
