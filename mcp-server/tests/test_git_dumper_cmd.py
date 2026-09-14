"""dump_exposed_git must invoke git-dumper with --proxy, not -p.

Regression: the installed arthaud/git-dumper CLI accepts `--proxy URL` only;
the code passed `-p http://127.0.0.1:8080`, which the CLI rejects with rc=2
("unrecognized arguments"), so every dump against a proxied target failed and
the tool built for exposed-.git labs never ran.
"""

from __future__ import annotations

import unittest

from praetor.tools.secrets.git_dumper import _git_dumper_cmd


class GitDumperCmdTest(unittest.TestCase):

    def test_uses_long_proxy_flag(self):
        cmd = _git_dumper_cmd(
            "git-dumper", "https://t.example/.git/", "/out", "http://127.0.0.1:8080")
        self.assertIn("--proxy", cmd)
        self.assertNotIn("-p", cmd)
        # --proxy must be immediately followed by the proxy URL.
        self.assertEqual(cmd[cmd.index("--proxy") + 1], "http://127.0.0.1:8080")

    def test_positional_url_and_dir_order(self):
        cmd = _git_dumper_cmd(
            "git-dumper", "https://t.example/.git/", "/out/dir", "http://127.0.0.1:8080")
        # arthaud/git-dumper: [options] URL DIR — tool first, URL before DIR.
        self.assertEqual(cmd[0], "git-dumper")
        u, d = cmd.index("https://t.example/.git/"), cmd.index("/out/dir")
        self.assertLess(u, d)


if __name__ == "__main__":
    unittest.main()
