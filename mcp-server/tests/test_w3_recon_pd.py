"""Wave 3 — ProjectDiscovery suite + graphw00f wrappers."""

import asyncio
import unittest
from unittest import mock

from burpsuite_mcp.tools import recon_pd


class W3HelpersTest(unittest.TestCase):

    def test_not_installed_message_has_install_hint(self):
        msg = recon_pd._not_installed("foo", "go install foo@latest")
        self.assertIn("Error: foo not installed", msg)
        self.assertIn("go install foo@latest", msg)

    def test_parse_jsonl_skips_junk(self):
        out = recon_pd._parse_jsonl("""
{"a": 1}
not-json
{"b": 2}
""".strip())
        self.assertEqual(out, [{"a": 1}, {"b": 2}])


class W3ToolRegistrationTest(unittest.TestCase):

    def test_all_pd_tools_registered(self):
        tools = []

        class _Stub:
            def tool(self):
                def _wrap(fn):
                    tools.append(fn.__name__)
                    return fn
                return _wrap

        recon_pd.register(_Stub())
        for t in ("run_dnsx", "run_naabu", "run_tlsx", "run_asnmap",
                  "run_uncover", "run_cloudlist", "run_notify",
                  "run_mapcves", "run_cdncheck", "run_alterx",
                  "run_graphw00f"):
            self.assertIn(t, tools, f"missing tool {t}")


class W3MissingBinaryFallsThroughTest(unittest.TestCase):

    def _call(self, tool_name, *args, **kwargs):
        async def _async():
            # tools are registered via decorator; capture them by re-registering
            holders: dict = {}

            class _Stub:
                def tool(self):
                    def _wrap(fn):
                        holders[fn.__name__] = fn
                        return fn
                    return _wrap

            recon_pd.register(_Stub())
            return await holders[tool_name](*args, **kwargs)

        return asyncio.run(_async())

    def test_dnsx_returns_install_hint(self):
        with mock.patch.object(recon_pd, "_check_tool", return_value=False):
            out = self._call("run_dnsx", ["example.com"])
        self.assertIn("dnsx not installed", out)
        self.assertIn("go install", out)

    def test_graphw00f_returns_install_hint(self):
        with mock.patch.object(recon_pd, "_check_tool", return_value=False):
            out = self._call("run_graphw00f", "https://example.com/graphql")
        self.assertIn("graphw00f", out)
        self.assertIn("install", out.lower())

    def test_naabu_returns_install_hint(self):
        with mock.patch.object(recon_pd, "_check_tool", return_value=False):
            out = self._call("run_naabu", "1.1.1.1")
        self.assertIn("naabu not installed", out)


if __name__ == "__main__":
    unittest.main()
