"""W22-e — SAST → DAST risk-rank handoff tests."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp.tools.sast_handoff import (
    _classify_rule,
    _walk_back_for_route,
    _aggregate_endpoints,
    _parse_opengrep_blob,
)


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class RuleClassifierTest(unittest.TestCase):

    def test_sqli_rule(self):
        vt, score = _classify_rule("python.django.security.sql-injection-via-raw")
        self.assertEqual(vt, "sqli")
        self.assertGreaterEqual(score, 8)

    def test_xss_rule(self):
        vt, _ = _classify_rule("javascript.express.xss.via-document-write")
        self.assertEqual(vt, "xss")

    def test_rce_rule(self):
        vt, score = _classify_rule("java.lang.security.os-command-injection")
        self.assertEqual(vt, "rce")
        self.assertEqual(score, 10)

    def test_unknown_falls_back_to_generic(self):
        vt, score = _classify_rule("totally.unknown.rule.id")
        self.assertEqual(vt, "generic_sink")
        self.assertEqual(score, 3)

    def test_deserialization_pickle_route(self):
        vt, _ = _classify_rule("python.lang.security.deserialization.unsafe-pickle")
        self.assertEqual(vt, "deserialization")


class RouteWalkbackTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-sast-route-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, content: str) -> Path:
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def test_flask_route_extracted(self):
        p = self._write("app.py", '\n'.join([
            'from flask import Flask, request',
            'app = Flask(__name__)',
            '',
            '@app.route("/login", methods=["POST"])',
            'def login():',
            '    user = request.form["user"]',  # line 6 — vuln finding here
            '    db.execute("SELECT * FROM users WHERE name=" + user)',  # line 7
        ]))
        route = _walk_back_for_route(p, line=7)
        self.assertEqual(route["framework"], "flask")
        self.assertEqual(route["method"], "POST")
        self.assertEqual(route["path"], "/login")

    def test_fastapi_route_extracted(self):
        p = self._write("api.py", '\n'.join([
            'from fastapi import FastAPI',
            'app = FastAPI()',
            '',
            '@app.post("/users/{id}")',
            'def update_user(id: str, body: dict):',
            '    return run_sql(f"UPDATE users SET data={body} WHERE id={id}")',
        ]))
        route = _walk_back_for_route(p, line=6)
        self.assertEqual(route["framework"], "fastapi")
        self.assertEqual(route["method"], "POST")
        self.assertEqual(route["path"], "/users/{id}")

    def test_express_route_extracted(self):
        p = self._write("server.js", '\n'.join([
            'const app = express()',
            '',
            'app.get("/api/search", (req, res) => {',
            '  db.query("SELECT * FROM items WHERE name=\'" + req.query.q + "\'")',
            '})',
        ]))
        route = _walk_back_for_route(p, line=4)
        self.assertEqual(route["framework"], "express")
        self.assertEqual(route["method"], "GET")
        self.assertEqual(route["path"], "/api/search")

    def test_spring_route_extracted(self):
        p = self._write("Ctrl.java", '\n'.join([
            'public class Ctrl {',
            '    @GetMapping("/profile/{id}")',
            '    public String profile(@PathVariable String id) {',
            '        return jdbc.query("SELECT * FROM users WHERE id=" + id);',
            '    }',
            '}',
        ]))
        route = _walk_back_for_route(p, line=4)
        self.assertEqual(route["framework"], "spring")
        self.assertEqual(route["method"], "GET")
        self.assertEqual(route["path"], "/profile/{id}")

    def test_nextjs_app_route_filesystem(self):
        p = self.tmp / "app" / "api" / "auth" / "route.ts"
        p.parent.mkdir(parents=True)
        p.write_text("export async function POST(req) { /* sink */ }")
        route = _walk_back_for_route(p, line=1)
        self.assertEqual(route["framework"], "nextjs_app_router")
        self.assertEqual(route["path"], "/api/auth")

    def test_nextjs_pages_api_filesystem(self):
        p = self.tmp / "pages" / "api" / "users.ts"
        p.parent.mkdir(parents=True)
        p.write_text("export default function handler() {}")
        route = _walk_back_for_route(p, line=1)
        self.assertEqual(route["framework"], "nextjs_pages_api")
        self.assertEqual(route["path"], "/api/users")

    def test_no_route_returns_empty(self):
        p = self._write("misc.py", 'def helper():\n    return 1\n')
        route = _walk_back_for_route(p, line=2)
        self.assertEqual(route, {})


class AggregateEndpointsTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-sast-agg-"))
        # Two source files, two endpoints.
        (self.tmp / "a.py").write_text('\n'.join([
            '@app.route("/login", methods=["POST"])',
            'def login():',
            '    sql_inject_sink(request.form["u"])',  # line 3
            '    xss_sink(request.form["msg"])',       # line 4
        ]))
        (self.tmp / "b.py").write_text('\n'.join([
            '@app.route("/profile")',
            'def profile():',
            '    weak_crypto_sink()',  # line 3
        ]))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_two_endpoints_aggregated_with_summed_risk(self):
        findings = [
            {"check_id": "python.flask.sql-injection", "path": "a.py",
             "start": {"line": 3}, "extra": {"severity": "ERROR", "lines": "sql sink"}},
            {"check_id": "python.flask.xss-template", "path": "a.py",
             "start": {"line": 4}, "extra": {"severity": "WARNING", "lines": "xss sink"}},
            {"check_id": "python.lang.weak-crypto", "path": "b.py",
             "start": {"line": 3}, "extra": {"severity": "INFO", "lines": "md5"}},
        ]
        out = _aggregate_endpoints(findings, self.tmp)
        # Drop the orphans-tail entry if present.
        ranked = [e for e in out if "endpoint" not in e or e.get("path")]
        # /login should outrank /profile (sqli + xss vs weak-crypto info).
        endpoints = [(e["method"], e["path"]) for e in ranked if "path" in e]
        self.assertIn(("POST", "/login"), endpoints)
        self.assertIn(("GET", "/profile"), endpoints)
        first = ranked[0]
        self.assertEqual(first["path"], "/login")
        self.assertIn("sqli", first["vuln_classes"])
        self.assertIn("xss", first["vuln_classes"])
        self.assertGreater(first["risk_score"], ranked[1]["risk_score"])

    def test_unmapped_finding_lands_in_orphans(self):
        (self.tmp / "no_route.py").write_text('def x():\n    sink()\n')
        findings = [
            {"check_id": "python.lang.os-command", "path": "no_route.py",
             "start": {"line": 2}, "extra": {"severity": "ERROR", "lines": "exec"}},
        ]
        out = _aggregate_endpoints(findings, self.tmp)
        orphans_entries = [e for e in out if "orphans" in e]
        self.assertEqual(len(orphans_entries), 1)
        self.assertEqual(len(orphans_entries[0]["orphans"]), 1)


class SastToEndpointRiskToolTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-sast-tool-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_inline_json_blob_accepted(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        # Build a minimal opengrep --json blob inline.
        (self.tmp / "v.py").write_text('@app.route("/x")\ndef v():\n    sqli_sink()\n')
        blob = json.dumps({
            "results": [{
                "check_id": "python.flask.sql-injection",
                "path": "v.py",
                "start": {"line": 3},
                "extra": {"severity": "ERROR", "lines": "sqli_sink()"},
            }]
        })
        out = await captured["sast_to_endpoint_risk"](
            opengrep_json=blob, source_root=str(self.tmp),
        )
        self.assertEqual(out["total_findings"], 1)
        self.assertEqual(out["ranked_endpoints"][0]["path"], "/x")
        self.assertIn("sqli", out["ranked_endpoints"][0]["vuln_classes"])

    async def test_path_to_json_file_accepted(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        (self.tmp / "v.py").write_text('@app.route("/y")\ndef v():\n    rce_sink()\n')
        json_file = self.tmp / "report.json"
        json_file.write_text(json.dumps({
            "results": [{
                "check_id": "python.lang.os-command-injection",
                "path": "v.py",
                "start": {"line": 3},
                "extra": {"severity": "ERROR", "lines": "rce_sink()"},
            }]
        }))
        out = await captured["sast_to_endpoint_risk"](
            opengrep_json=str(json_file), source_root=str(self.tmp),
        )
        self.assertEqual(out["total_findings"], 1)
        self.assertEqual(out["ranked_endpoints"][0]["vuln_classes"], ["rce"])

    async def test_missing_path_returns_error(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        out = await captured["sast_to_endpoint_risk"](
            opengrep_json=str(self.tmp / "nonexistent.json"),
        )
        self.assertIn("error", out)


class RiskRankEndpointsToolTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-sast-risk-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_missing_opengrep_returns_error(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        with patch("burpsuite_mcp.tools.sast_handoff._check_tool", return_value=False):
            out = await captured["risk_rank_endpoints"](target_path=str(self.tmp))
        self.assertIn("error", out)
        self.assertIn("opengrep", out["error"].lower())

    async def test_missing_target_returns_error(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        with patch("burpsuite_mcp.tools.sast_handoff._check_tool", return_value=True):
            out = await captured["risk_rank_endpoints"](
                target_path=str(self.tmp / "nonexistent"),
            )
        self.assertIn("error", out)

    async def test_end_to_end_with_mocked_opengrep(self):
        from burpsuite_mcp.tools import sast_handoff
        stub, captured = _stub_mcp()
        sast_handoff.register(stub)
        # Seed a source file with an inferable route.
        (self.tmp / "x.py").write_text('@app.route("/api/z")\ndef v():\n    ssrf_sink(request.args["u"])\n')

        async def fake_run_cmd(cmd, **kw):
            return (json.dumps({
                "results": [{
                    "check_id": "python.lang.ssrf",
                    "path": "x.py",
                    "start": {"line": 3},
                    "extra": {"severity": "ERROR", "lines": "ssrf_sink(...)"},
                }]
            }), "", 0)

        with patch("burpsuite_mcp.tools.sast_handoff._check_tool", return_value=True), \
             patch("burpsuite_mcp.tools.sast_handoff._run_cmd", new=fake_run_cmd):
            out = await captured["risk_rank_endpoints"](target_path=str(self.tmp))
        self.assertEqual(out["total_findings"], 1)
        self.assertEqual(out["ranked_endpoints"][0]["path"], "/api/z")
        self.assertIn("ssrf", out["ranked_endpoints"][0]["vuln_classes"])
        self.assertIn("opengrep_summary", out)


class ToolsRegisteredTest(unittest.TestCase):

    def test_both_tools_in_server(self):
        from burpsuite_mcp import server
        tools = server.mcp._tool_manager._tools
        self.assertIn("sast_to_endpoint_risk", tools)
        self.assertIn("risk_rank_endpoints", tools)


if __name__ == "__main__":
    unittest.main()
