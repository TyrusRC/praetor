"""SecLists path detection: env var, common paths, missing-with-hint."""
import os
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest import mock

from burpsuite_mcp.tools.recon import scanning


class SecListsDetectionTest(unittest.TestCase):
    def test_env_var_wins(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "Discovery").mkdir()
            with mock.patch.dict(os.environ, {"SECLISTS_PATH": tmp}):
                self.assertEqual(scanning.detect_seclists(), tmp)

    def test_common_path_fallback(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "Discovery").mkdir()
            with mock.patch.dict(os.environ, {}, clear=True):
                with mock.patch.object(
                    scanning, "_SECLISTS_CANDIDATES", [tmp, "/nonexistent"]
                ):
                    self.assertEqual(scanning.detect_seclists(), tmp)

    def test_missing_returns_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(scanning, "_SECLISTS_CANDIDATES", ["/nonexistent"]):
                self.assertIsNone(scanning.detect_seclists())


if __name__ == "__main__":
    unittest.main()
