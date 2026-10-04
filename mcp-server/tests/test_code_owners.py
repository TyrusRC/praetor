"""suggest_finding_owner — CODEOWNERS matching + git-blame attribution.

Pure helpers are unit-tested; the tool is driven end-to-end against a real
throwaway git repo (skipped if git is unavailable).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from praetor.tools import code_owners as C


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class CodeownersParseTest(unittest.TestCase):

    def test_parse_skips_comments_and_bare(self):
        text = "# comment\n\n*.py @py-team\n/src/ @src-team @lead\nnoowner\n"
        rules = C._parse_codeowners(text)
        self.assertEqual(rules, [("*.py", ["@py-team"]), ("/src/", ["@src-team", "@lead"])])

    def test_match_last_rule_wins(self):
        rules = [("*", ["@default"]), ("/src/", ["@src"]), ("*.py", ["@py"]),
                 ("src/app/auth.py", ["@auth-owner"])]
        self.assertEqual(C._match_codeowners("src/app/auth.py", rules), ["@auth-owner"])
        self.assertEqual(C._match_codeowners("src/util.py", rules), ["@py"])
        self.assertEqual(C._match_codeowners("README.md", rules), ["@default"])

    def test_no_match(self):
        self.assertEqual(C._match_codeowners("x.go", [("*.py", ["@py"])]), [])

    def test_blame_porcelain_parse(self):
        out = ("a1b2c3d4e5f6 1 1 1\nauthor Jane Dev\nauthor-mail <jane@acme.io>\n"
               "summary fix auth check\n\tcode here\n")
        info = C._parse_blame_porcelain(out)
        self.assertEqual(info["author"], "Jane Dev")
        self.assertEqual(info["author_mail"], "jane@acme.io")
        self.assertEqual(info["commit"], "a1b2c3d4e5f6")
        self.assertEqual(info["summary"], "fix auth check")


@unittest.skipIf(shutil.which("git") is None, "git not available")
class SuggestOwnerIntegrationTest(unittest.IsolatedAsyncioTestCase):

    async def test_codeowners_and_blame(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "src").mkdir()
            (repo / "src" / "auth.py").write_text("def login():\n    return True\n")
            (repo / "CODEOWNERS").write_text("*.py @py-team\n/src/ @auth-owner\n")
            env = {"GIT_AUTHOR_NAME": "Jane Dev", "GIT_AUTHOR_EMAIL": "jane@acme.io",
                   "GIT_COMMITTER_NAME": "Jane Dev", "GIT_COMMITTER_EMAIL": "jane@acme.io"}
            import os
            runenv = {**os.environ, **env}
            subprocess.run(["git", "init", "-q"], cwd=d, check=True)
            subprocess.run(["git", "add", "-A"], cwd=d, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=d, env=runenv, check=True)

            out = await _fn("suggest_finding_owner")(repo_path=d, file="src/auth.py", line=2)
            self.assertIn("@auth-owner", out)        # last matching CODEOWNERS rule
            self.assertIn("Jane Dev", out)           # git blame author

    async def test_traversal_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = await _fn("suggest_finding_owner")(repo_path=d, file="../../etc/passwd")
        self.assertIn("outside the repo", out)


if __name__ == "__main__":
    unittest.main()
