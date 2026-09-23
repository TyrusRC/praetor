"""Go bin dir resolution for ProjectDiscovery tools — honor GOBIN/GOPATH so a
custom-GOPATH host (macOS blocker) doesn't hide correctly-installed binaries."""

import importlib
import os
import unittest
from unittest.mock import patch


def _go_bin_with_env(**env):
    """Reimport _common under a patched environment and read its resolver."""
    with patch.dict(os.environ, env, clear=False):
        # drop the keys not provided so a leaked GOBIN/GOPATH doesn't skew the test
        for k in ("GOBIN", "GOPATH"):
            if k not in env:
                os.environ.pop(k, None)
        from praetor.tools.recon import _common
        return _common._go_bin()


class GoBinResolutionTest(unittest.TestCase):
    def test_gobin_wins(self):
        self.assertEqual(_go_bin_with_env(GOBIN="/opt/go/bin"), "/opt/go/bin")

    def test_gopath_bin_when_no_gobin(self):
        self.assertEqual(_go_bin_with_env(GOPATH="/Users/x/dev/go"),
                         os.path.join("/Users/x/dev/go", "bin"))

    def test_gopath_first_entry_on_list(self):
        gp = os.pathsep.join(["/a/go", "/b/go"])
        self.assertEqual(_go_bin_with_env(GOPATH=gp), os.path.join("/a/go", "bin"))

    def test_default_home_go_bin(self):
        self.assertEqual(_go_bin_with_env(),
                         os.path.join(os.path.expanduser("~"), "go", "bin"))


if __name__ == "__main__":
    unittest.main()
