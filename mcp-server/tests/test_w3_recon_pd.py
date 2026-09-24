"""Wave 3 — ProjectDiscovery suite + graphw00f wrappers."""

import asyncio
import unittest
from unittest import mock

from praetor.tools import recon_pd


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
                  "run_vulnx", "run_cdncheck", "run_alterx",
                  "run_graphw00f"):
            self.assertIn(t, tools, f"missing tool {t}")


class W3TlsxFlagTest(unittest.TestCase):
    """Regression: tlsx rejects `-san`/`-cn` combined with any probe with
    'san or cn flag cannot be used with other probes' — every baremetal call
    failed. `-json` already carries subject_cn/subject_an, so the display flags
    are dropped and only the probe (`-jarm`/`-expired`) stays."""

    def test_tlsx_does_not_combine_san_cn_with_probes(self):
        captured: dict = {}

        async def fake_run_cmd(cmd, **kwargs):
            captured["cmd"] = cmd
            return ("", "", 0)

        async def _async():
            holders: dict = {}

            class _Stub:
                def tool(self):
                    def _wrap(fn):
                        holders[fn.__name__] = fn
                        return fn
                    return _wrap

            recon_pd.register(_Stub())
            with mock.patch.object(recon_pd._impl, "_check_tool", return_value=True), \
                 mock.patch.object(recon_pd._impl, "_run_cmd", side_effect=fake_run_cmd):
                return await holders["run_tlsx"](["example.com"])

        asyncio.run(_async())
        cmd = captured["cmd"]
        has_probe = any(p in cmd for p in ("-jarm", "-expired", "-cipher"))
        self.assertTrue(has_probe, "tlsx should still request at least one probe")
        # The forbidden combination that made tlsx exit fatally.
        self.assertNotIn("-san", cmd)
        self.assertNotIn("-cn", cmd)


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
        with mock.patch.object(recon_pd._impl, "_check_tool", return_value=False):
            out = self._call("run_dnsx", ["example.com"])
        self.assertIn("dnsx not installed", out)
        self.assertIn("go install", out)

    def test_graphw00f_returns_install_hint(self):
        with mock.patch.object(recon_pd._impl, "_check_tool", return_value=False):
            out = self._call("run_graphw00f", "https://example.com/graphql")
        self.assertIn("graphw00f", out)
        self.assertIn("install", out.lower())

    def test_naabu_returns_install_hint(self):
        with mock.patch.object(recon_pd._impl, "_check_tool", return_value=False):
            out = self._call("run_naabu", "1.1.1.1")
        self.assertIn("naabu not installed", out)


if __name__ == "__main__":
    unittest.main()
