import os
import tempfile
import unittest
from pathlib import Path

from burpsuite_mcp.tools.workspace import workspace_paths, ensure_workspace


class TestWorkspace(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_paths_has_all_keys(self):
        p = workspace_paths("example.com")
        for k in ("root", "findings", "artifacts", "screenshots", "captures", "poc",
                  "testcases", "reports", "material", "wordlists", "tool_output"):
            self.assertIn(k, p)
        self.assertTrue(str(p["screenshots"]).endswith("artifacts/screenshots"))

    def test_ensure_is_idempotent(self):
        ensure_workspace("example.com")
        p = ensure_workspace("example.com")  # second call must not raise
        for path in p.values():
            self.assertTrue(Path(path).exists())

    def test_traversal_rejected(self):
        with self.assertRaises(ValueError):
            workspace_paths("../../etc")


if __name__ == "__main__":
    unittest.main()
