"""run_droopescan — CMS gap filler (Drupal/Joomla) beside WordPress-only wpscan."""

import asyncio
import unittest
from unittest import mock

from praetor.tools.recon.scanning.vuln_scan import _g2


def _tools():
    holders: dict = {}

    class _Stub:
        def tool(self):
            def _wrap(fn):
                holders[fn.__name__] = fn
                return fn
            return _wrap

    _g2.register(_Stub())
    return holders


class DroopescanTest(unittest.TestCase):

    def test_registered(self):
        self.assertIn("run_droopescan", _tools())

    def test_not_installed_hint(self):
        fn = _tools()["run_droopescan"]
        with mock.patch.object(_g2, "_check_tool", return_value=False):
            out = asyncio.run(fn("https://t.example"))
        self.assertIn("droopescan not installed", out)
        self.assertIn("pip install droopescan", out)

    def test_bad_cms_rejected_before_running(self):
        fn = _tools()["run_droopescan"]
        ran = {"called": False}

        async def fake_run(cmd, timeout=600):
            ran["called"] = True
            return ("", "", 0)

        with mock.patch.object(_g2, "_check_tool", return_value=True), \
             mock.patch.object(_g2, "_run_cmd", side_effect=fake_run):
            out = asyncio.run(fn("https://t.example", cms="bogus"))
        self.assertIn("cms must be one of", out)
        self.assertFalse(ran["called"], "must not execute droopescan on an invalid cms")

    def test_valid_cms_builds_scan_command(self):
        fn = _tools()["run_droopescan"]
        captured: dict = {}

        async def fake_run(cmd, timeout=600):
            captured["cmd"] = cmd
            return ("[+] Possible version(s):\n  8.9.1", "", 0)

        with mock.patch.object(_g2, "_check_tool", return_value=True), \
             mock.patch.object(_g2, "_run_cmd", side_effect=fake_run):
            out = asyncio.run(fn("https://t.example", cms="joomla"))
        self.assertEqual(captured["cmd"][:3], ["droopescan", "scan", "joomla"])
        self.assertIn("--url", captured["cmd"])
        self.assertIn("8.9.1", out)


if __name__ == "__main__":
    unittest.main()
