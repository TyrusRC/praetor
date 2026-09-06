"""Regression: tool modules that call `client.<verb>(...)` must bind `client`.

Several tools reference the shared `praetor.client` HTTP singleton from inside
their `@mcp.tool()` wrapper but forgot `from praetor import client`. The call
only fails at runtime (NameError: name 'client' is not defined) on the live
path, which the helper-level unit tests never exercise. Assert the module
global exists so the miss is caught at import time instead.
"""

import importlib
import unittest


class ClientBindingTest(unittest.TestCase):
    # (module path, attribute that must resolve to the HTTP client)
    MODULES = [
        "praetor.tools.edge.test_graphql",
        "praetor.tools.smart_request_triage",
        "praetor.tools.notes.poc_bundle",
    ]

    def test_client_is_bound(self):
        for mod_path in self.MODULES:
            mod = importlib.import_module(mod_path)
            self.assertTrue(
                hasattr(mod, "client"),
                f"{mod_path} calls client.* but does not import `client` "
                f"— live path raises NameError",
            )


if __name__ == "__main__":
    unittest.main()
