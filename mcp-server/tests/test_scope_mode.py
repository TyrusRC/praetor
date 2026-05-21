"""Scope-mode persistence — operator vs strict, on-disk roundtrip."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from burpsuite_mcp.tools import _scope_mode


class ScopeModePersistenceTest(unittest.TestCase):
    def test_default_is_operator(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                self.assertEqual(_scope_mode.get_mode(), "operator")

    def test_set_then_get_strict(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                _scope_mode.set_mode("strict")
                self.assertEqual(_scope_mode.get_mode(), "strict")
                state_file = Path(tmp) / "_scope_mode.json"
                self.assertTrue(state_file.exists())
                self.assertEqual(
                    json.loads(state_file.read_text())["mode"], "strict"
                )

    def test_invalid_mode_rejected(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.object(_scope_mode, "_intel_dir", lambda: Path(tmp)):
                with self.assertRaises(ValueError):
                    _scope_mode.set_mode("loose")


if __name__ == "__main__":
    unittest.main()
