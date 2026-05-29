"""Smoke + behavioural tests for the W7 new tools — registration, schemas,
and a few sanity checks per tool. Not full functional tests (those need a
live Burp), but enough to catch contract drift.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class CVSSToolTest(unittest.IsolatedAsyncioTestCase):

    async def test_compute_cvss_returns_vectors(self):
        from burpsuite_mcp.tools import advisor
        stub, captured = _stub_mcp()
        advisor.register(stub)
        cvss = captured["compute_cvss"]
        out = await cvss(vuln_type="sqli", requires_auth=False)
        self.assertIn("cvss4_vector", out)
        self.assertIn("cvss31_vector", out)
        self.assertIn("cvss4_band", out)
        self.assertEqual(out["cvss4_band"], "High")


class RankTargetsTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_endpoints_returns_note(self):
        from burpsuite_mcp.tools.scan import rank_targets
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            os.chdir(td)
            try:
                stub, captured = _stub_mcp()
                rank_targets.register(stub)
                out = await captured["rank_attack_targets"](domain="x.example.com")
                self.assertEqual(out["targets"], [])
                self.assertIn("note", out)
            finally:
                os.chdir(cwd)

    async def test_inline_endpoints_scored(self):
        from burpsuite_mcp.tools.scan import rank_targets
        stub, captured = _stub_mcp()
        rank_targets.register(stub)
        out = await captured["rank_attack_targets"](
            domain="x.example.com",
            endpoints=[
                {"method": "POST", "path": "/admin/users", "body_keys": ["role", "id"]},
                {"method": "GET", "path": "/health", "parameters": ["q"]},
            ],
            top_k=10,
        )
        self.assertGreaterEqual(len(out["targets"]), 1)
        self.assertEqual(out["targets"][0]["method"], "POST")
        self.assertIn("/admin", out["targets"][0]["path"])


class InvariantsTest(unittest.IsolatedAsyncioTestCase):

    async def test_inline_schema_endpoints(self):
        from burpsuite_mcp.tools.testing_extended import business_invariants
        stub, captured = _stub_mcp()
        business_invariants.register(stub)
        out = await captured["infer_business_invariants"](
            domain="x.example.com",
            api_schema_endpoints=[
                {"path": "/checkout", "method": "POST", "body_keys": ["price", "qty", "total"]},
                {"path": "/payment", "method": "POST", "body_keys": ["card", "amount"]},
                {"path": "/confirm", "method": "POST", "body_keys": ["order_id"]},
                {"path": "/transfer", "method": "POST", "body_keys": ["amount", "idempotency_key"]},
            ],
        )
        cats = {i["category"] for i in out["invariants"]}
        self.assertIn("price_arithmetic", cats)
        self.assertIn("idempotency", cats)
        # state machine for checkout / payment / confirm flow should appear
        flows = {i.get("flow") for i in out["invariants"] if i["category"] == "state_machine"}
        self.assertIn("checkout_flow", flows)


class BenchmarkTest(unittest.IsolatedAsyncioTestCase):

    async def test_run_autopenbench_awaits_flag(self):
        from burpsuite_mcp.tools import benchmark
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            os.chdir(td)
            try:
                with patch.object(benchmark, "_check_tool", return_value=True):
                    stub, captured = _stub_mcp()
                    benchmark.register(stub)
                    out = await captured["run_autopenbench"](
                        challenge_id="demo-rce-1",
                        challenge_path=td,
                    )
                    self.assertEqual(out["status"], "awaiting_grow_agent")
                    self.assertIn("demo-rce-1", out["flag_path"])
            finally:
                os.chdir(cwd)

    async def test_summarize_empty(self):
        from burpsuite_mcp.tools import benchmark
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            os.chdir(td)
            try:
                stub, captured = _stub_mcp()
                benchmark.register(stub)
                out = await captured["summarize_benchmarks"]()
                self.assertEqual(out["total_runs"], 0)
            finally:
                os.chdir(cwd)


class SourceAwareTest(unittest.IsolatedAsyncioTestCase):

    async def test_xvulnhuntr_missing_path(self):
        from burpsuite_mcp.tools import source_aware
        stub, captured = _stub_mcp()
        source_aware.register(stub)
        out = await captured["run_xvulnhuntr"](repo_path="/nonexistent/xyz")
        self.assertIn("error", out)
        self.assertIn("not found", out["error"])

    async def test_xvulnhuntr_install_hint(self):
        from burpsuite_mcp.tools import source_aware
        with tempfile.TemporaryDirectory() as td:
            with patch.object(source_aware, "_check_tool", return_value=False):
                stub, captured = _stub_mcp()
                source_aware.register(stub)
                out = await captured["run_xvulnhuntr"](repo_path=td)
                self.assertIn("error", out)
                self.assertIn("hint", out)
                self.assertIn("xvulnhuntr", out["hint"])


class PocBundleTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_findings_returns_error(self):
        from burpsuite_mcp.tools.notes import poc_bundle
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            os.chdir(td)
            try:
                stub, captured = _stub_mcp()
                poc_bundle.register(stub)
                out = await captured["export_poc_bundle"](
                    domain="x.example.com", finding_id="f1"
                )
                self.assertIn("error", out)
            finally:
                os.chdir(cwd)


class FuzzEvoTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_seed_returns_error_verdict(self):
        from burpsuite_mcp.tools.testing import fuzz_evolutionary
        stub, captured = _stub_mcp()
        fuzz_evolutionary.register(stub)
        out = await captured["fuzz_evolutionary"](
            url="http://example.com", parameter="q", seed="", signals={"status_in": [500]}
        )
        self.assertEqual(out["verdict"], "ERROR")


if __name__ == "__main__":
    unittest.main()
