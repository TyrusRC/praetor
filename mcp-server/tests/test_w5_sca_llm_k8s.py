"""Wave 5 — SCA + LLM red-team + k8s + smuggle + vulnwalker + HTTPQL."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from burpsuite_mcp.tools import (
    httpql,
    k8s_audit,
    llm_redteam,
    sca,
    smuggle_cli,
    vulnwalker,
)


class W5RegistrationTest(unittest.TestCase):

    def _registered(self, module):
        tools = []

        class _Stub:
            def tool(self):
                def _wrap(fn):
                    tools.append(fn.__name__)
                    return fn
                return _wrap

        module.register(_Stub())
        return tools

    def test_sca_tools_registered(self):
        for t in ("run_osv_scanner", "run_trivy", "run_grype"):
            self.assertIn(t, self._registered(sca))

    def test_llm_redteam_tools_registered(self):
        for t in ("run_garak", "run_pyrit_orchestrator", "run_mcp_scan"):
            self.assertIn(t, self._registered(llm_redteam))

    def test_k8s_tools_registered(self):
        for t in ("run_kubescape", "run_kube_hunter"):
            self.assertIn(t, self._registered(k8s_audit))

    def test_smuggle_registered(self):
        self.assertIn("run_smuggle", self._registered(smuggle_cli))

    def test_vulnwalker_registered(self):
        self.assertIn("vulnwalker_audit", self._registered(vulnwalker))

    def test_httpql_registered(self):
        self.assertIn("query_history_dsl", self._registered(httpql))


class W5MissingBinaryFallbackTest(unittest.TestCase):

    def _call(self, module, tool_name, *args, **kwargs):
        async def _async():
            holders: dict = {}
            class _Stub:
                def tool(self):
                    def _wrap(fn):
                        holders[fn.__name__] = fn
                        return fn
                    return _wrap
            module.register(_Stub())
            return await holders[tool_name](*args, **kwargs)
        return asyncio.run(_async())

    def test_osv_scanner_install_hint(self):
        with mock.patch.object(sca, "_check_tool", return_value=False):
            out = self._call(sca, "run_osv_scanner", "./go.mod")
        self.assertIn("osv-scanner not installed", out)

    def test_trivy_install_hint(self):
        with mock.patch.object(sca, "_check_tool", return_value=False):
            out = self._call(sca, "run_trivy", "./repo")
        self.assertIn("trivy not installed", out)

    def test_garak_install_hint(self):
        with mock.patch.object(llm_redteam, "_check_tool", return_value=False):
            out = self._call(llm_redteam, "run_garak", "gpt-4o")
        self.assertIn("garak not installed", out)

    def test_mcp_scan_install_hint(self):
        with mock.patch.object(llm_redteam, "_check_tool", return_value=False):
            out = self._call(llm_redteam, "run_mcp_scan", "./server.py")
        self.assertIn("mcp-scan not installed", out)

    def test_kubescape_install_hint(self):
        with mock.patch.object(k8s_audit, "_check_tool", return_value=False):
            out = self._call(k8s_audit, "run_kubescape")
        self.assertIn("kubescape not installed", out)

    def test_kube_hunter_install_hint(self):
        with mock.patch.object(k8s_audit, "_check_tool", return_value=False):
            out = self._call(k8s_audit, "run_kube_hunter")
        self.assertIn("kube-hunter not installed", out)

    def test_smuggle_install_hint(self):
        with mock.patch.object(smuggle_cli, "_check_tool", return_value=False):
            out = self._call(smuggle_cli, "run_smuggle", "https://x.test/")
        self.assertIn("smuggle not installed", out)


class W5VulnwalkerTest(unittest.TestCase):

    def test_sinks_table_includes_canonical(self):
        for s in ("eval", "exec", "system", "Popen", "pickle.loads",
                  "yaml.load", "render_template_string", "execute"):
            self.assertIn(s, vulnwalker._SINKS)

    def test_sources_table_includes_flask_request(self):
        for s in ("request.args", "request.form", "request.json", "sys.argv"):
            self.assertIn(s, vulnwalker._SOURCES)

    def test_walk_module_detects_eval(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evil.py"
            p.write_text(
                "from flask import request\n"
                "def h():\n"
                "    return eval(request.args.get('x'))\n"
            )
            findings = vulnwalker._walk_module(p)
        self.assertTrue(any(f["sink"] == "eval" for f in findings))
        self.assertTrue(any("request.args" in f["tainted_input"] for f in findings))


class W5HttpqlTest(unittest.TestCase):

    def test_tokenise_basic(self):
        out = httpql._tokenise("status >= 400 AND host = api.x.test")
        self.assertEqual(out, ["status", ">=", "400", "AND", "host", "=", "api.x.test"])

    def test_eval_clause_status_equals(self):
        e = {"status_code": 403, "url": "https://x.test/a"}
        self.assertTrue(httpql._eval_clause("status", "=", "403", e))
        self.assertFalse(httpql._eval_clause("status", "=", "200", e))

    def test_eval_clause_host_substring(self):
        e = {"url": "https://api.x.test/admin"}
        self.assertTrue(httpql._eval_clause("host", "~", "api.x.test", e))
        self.assertTrue(httpql._eval_clause("path", "~", "admin", e))

    def test_eval_query_and(self):
        e = {"status_code": 500, "url": "https://api.x.test/admin",
             "method": "POST"}
        self.assertTrue(httpql._eval_query("status >= 400 AND host ~ x.test", e))
        self.assertFalse(httpql._eval_query("status >= 400 AND method = GET", e))


if __name__ == "__main__":
    unittest.main()
