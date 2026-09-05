"""SQLMap WAF-bypass flags + Ghauri command builders (LostSec SQLMap/Ghauri note).

Pure command-builder coverage — no binary, no network.
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestSqlmapCmd(unittest.TestCase):
    def setUp(self):
        from praetor.tools.recon.scanning.vuln_scan._g2 import _sqlmap_cmd, _cap_tamper
        self.build = _sqlmap_cmd
        self.cap = _cap_tamper

    def _c(self, **kw):
        base = dict(target="http://t/?id=1", data="", cookie="", method="GET",
                    level=1, risk=1, technique="BEUSTQ", tamper="", dbms="",
                    hex_=False, random_agent=False, ignore_code="", batch=True,
                    use_proxy=False)
        base.update(kw)
        return self.build(**base)

    def test_tamper_capped_at_three(self):
        # note: never more than 3 tampers
        self.assertEqual(
            self.cap("between,randomcase,space2comment,charencode,percentage"),
            "between,randomcase,space2comment",
        )

    def test_waf_bypass_flags_present(self):
        cmd = self._c(tamper="space2comment,randomcase", dbms="mysql",
                      hex_=True, random_agent=True, ignore_code="403,500")
        s = " ".join(cmd)
        self.assertIn("--tamper space2comment,randomcase", s)
        self.assertIn("--dbms mysql", s)
        self.assertIn("--hex", cmd)
        self.assertIn("--random-agent", cmd)
        self.assertIn("--ignore-code 403,500", s)

    def test_no_flags_when_defaults(self):
        cmd = self._c()
        self.assertNotIn("--tamper", cmd)
        self.assertNotIn("--hex", cmd)
        self.assertNotIn("--dbms", cmd)

    def test_no_destructive_flags_ever(self):
        # detection-only surface — os-shell/dump/file-write are not reachable
        cmd = self._c(tamper="space2comment")
        s = " ".join(cmd)
        for bad in ("--os-shell", "--os-pwn", "--dump-all", "--file-write", "--file-read"):
            self.assertNotIn(bad, s)


class TestGhauriCmd(unittest.TestCase):
    def setUp(self):
        from praetor.tools.recon.scanning.vuln_scan._g2 import _ghauri_cmd
        self.build = _ghauri_cmd

    def _c(self, **kw):
        base = dict(target="http://t/?id=1", data="", cookie="", method="GET",
                    param="", level=1, technique="", dbms="", confirm=False,
                    time_sec=0, delay=0, prefix="", suffix="", random_agent=False,
                    use_proxy=False)
        base.update(kw)
        return self.build(**base)

    def test_binary_and_batch(self):
        cmd = self._c()
        self.assertEqual(cmd[0], "ghauri")
        self.assertIn("--batch", cmd)

    def test_evasion_flags(self):
        cmd = self._c(confirm=True, dbms="mysql", time_sec=10, delay=5,
                      prefix="')/**/", suffix="--+", random_agent=True)
        s = " ".join(cmd)
        self.assertIn("--confirm", cmd)
        self.assertIn("--dbms mysql", s)
        self.assertIn("--time-sec 10", s)
        self.assertIn("--delay 5", s)
        self.assertIn("--prefix ')/**/", s)
        self.assertIn("--random-agent", cmd)

    def test_level_capped_at_three(self):
        cmd = self._c(level=9)
        i = cmd.index("--level")
        self.assertEqual(cmd[i + 1], "3")


if __name__ == "__main__":
    unittest.main()
