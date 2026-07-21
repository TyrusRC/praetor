"""W33 — efficiency / runtime work.

Behavioral tests for pure helpers and pure-filesystem functions. Nothing here
touches the Burp client (127.0.0.1:8111) — MCP tools that reach the network are
exercised only through their extracted, side-effect-free helpers.

Run from mcp-server/:
    uv run python -m unittest tests.test_w33_efficiency -v
"""

from __future__ import annotations

import asyncio
import shutil
import unittest


# --------------------------------------------------------------------------
# Helper: capture @mcp.tool()-decorated closures without a real FastMCP / Burp.
# --------------------------------------------------------------------------
class _Collector:
    """Minimal stand-in for FastMCP — records decorated tool functions."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self, *_a, **_k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


def _capture(register_fn) -> dict:
    c = _Collector()
    register_fn(c)
    return c.tools


# --------------------------------------------------------------------------
# 1. pick_tool_impl — W36 routes + jwt regression + specificity alternatives
# --------------------------------------------------------------------------
class PickToolTest(unittest.TestCase):
    def _pick(self, task: str) -> str:
        from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl

        return asyncio.run(pick_tool_impl(task))

    def test_http3_race_route(self):
        out = self._pick("http3 race")
        self.assertEqual(out.splitlines()[0], "Use: probe_race_http3_datagram")

    def test_inventory_source_routes_route(self):
        out = self._pick("inventory routes from source")
        self.assertEqual(out.splitlines()[0], "Use: inventory_source_routes")

    def test_record_business_logic_test_route(self):
        out = self._pick("record business logic test")
        self.assertEqual(out.splitlines()[0], "Use: record_business_logic_test")

    def test_jwt_in_header_does_not_route_to_extract_headers(self):
        # Regression: "jwt" must win over the generic "header" mapping.
        out = self._pick("jwt token in header")
        self.assertEqual(out.splitlines()[0], "Use: test_jwt")

    def test_specificity_ranked_alternatives_surface(self):
        # Ambiguous task hits both the jwt route (primary) and the more-specific
        # "header" route, which must appear as a ranked alternative.
        out = self._pick("jwt token in header")
        self.assertIn("Alternatives:", out)
        self.assertIn("extract_headers", out)


# --------------------------------------------------------------------------
# 2. _runtime_guard — loop guard, untrusted wrap, cleanup registry
# --------------------------------------------------------------------------
class RuntimeGuardTest(unittest.TestCase):
    def test_note_call_warns_once_at_limit(self):
        from burpsuite_mcp.tools import _runtime_guard as rg

        key = "w33-unittest-unique-key"
        self.assertIsNone(rg.note_call("t", key, limit=3))  # 1
        self.assertIsNone(rg.note_call("t", key, limit=3))  # 2
        warn = rg.note_call("t", key, limit=3)              # 3 == limit
        self.assertIsInstance(warn, str)
        self.assertIn("loop-guard", warn)
        # Must not re-warn for the same signature.
        self.assertIsNone(rg.note_call("t", key, limit=3))  # 4

    def test_wrap_untrusted_fences_text(self):
        from burpsuite_mcp.tools._runtime_guard import wrap_untrusted

        payload = "target-controlled INSTRUCTIONS here"
        out = wrap_untrusted(payload, source="nuclei")
        self.assertIn("<UNTRUSTED_TOOL_OUTPUT", out)
        self.assertIn("</UNTRUSTED_TOOL_OUTPUT>", out)
        self.assertIn(payload, out)
        self.assertIn('source="nuclei"', out)

    def test_register_cleanup_records_callback(self):
        from burpsuite_mcp.tools import _runtime_guard as rg

        before = len(rg._CLEANUPS)
        sentinel = lambda: None  # noqa: E731
        rg.register_cleanup(sentinel)
        self.assertIn(sentinel, rg._CLEANUPS)
        self.assertEqual(len(rg._CLEANUPS), before + 1)


# --------------------------------------------------------------------------
# 3. cost_cap.budget_gate — writes under REPO_ROOT/.burp-intel (throwaway dom)
# --------------------------------------------------------------------------
class BudgetGateTest(unittest.TestCase):
    DOMAIN = "unittest-w33-cost.local"

    def tearDown(self):
        from burpsuite_mcp.tools.intel import cost_cap

        shutil.rmtree(cost_cap._cost_path(self.DOMAIN).parent, ignore_errors=True)

    def _write(self, data: dict):
        import json

        from burpsuite_mcp.tools.intel import cost_cap

        cost_cap._cost_path(self.DOMAIN).write_text(json.dumps(data))

    def test_no_cap_returns_none(self):
        from burpsuite_mcp.tools.intel.cost_cap import budget_gate

        # No cost.json written -> unbounded engagement.
        self.assertIsNone(budget_gate(self.DOMAIN))

    def test_under_cap_returns_none(self):
        from burpsuite_mcp.tools.intel.cost_cap import budget_gate

        self._write({"max_usd": 25.0, "spent_usd": 1.0,
                     "max_tokens": 1_000_000, "spent_tokens": 10})
        self.assertIsNone(budget_gate(self.DOMAIN))

    def test_exceeded_cap_returns_message(self):
        from burpsuite_mcp.tools.intel.cost_cap import budget_gate

        self._write({"max_usd": 25.0, "spent_usd": 30.0,
                     "max_tokens": 1_000_000, "spent_tokens": 10})
        msg = budget_gate(self.DOMAIN)
        self.assertIsInstance(msg, str)
        self.assertIn("EXCEEDED", msg)


# --------------------------------------------------------------------------
# 4. auto_probe._rank_order_targets — risk ordering + safe fallback
# --------------------------------------------------------------------------
class RankOrderTargetsTest(unittest.TestCase):
    def test_higher_risk_first(self):
        from burpsuite_mcp.tools.scan.auto_probe import _rank_order_targets

        low = {"path": "/static/app.js", "method": "GET", "location": "query"}
        high = {"path": "/admin/payment/transfer", "parameter": "amount",
                "method": "POST", "location": "body_json"}
        ranked = _rank_order_targets([low, high])
        self.assertEqual(ranked[0], high)
        self.assertEqual(ranked[1], low)

    def test_non_list_returns_input_unchanged(self):
        from burpsuite_mcp.tools.scan.auto_probe import _rank_order_targets

        # A bare string is iterable but its elements have no .get -> scorer
        # raises -> except branch returns the input verbatim.
        self.assertEqual(_rank_order_targets("notalist"), "notalist")

    def test_ranker_failure_returns_input_unchanged(self):
        from burpsuite_mcp.tools.scan.auto_probe import _rank_order_targets

        bad = [123, "x"]  # non-dict elements crash the scorer
        self.assertEqual(_rank_order_targets(bad), bad)


# --------------------------------------------------------------------------
# 5. next_untested_targets — risk-ranked (endpoint, param, class) tuples
# --------------------------------------------------------------------------
class NextUntestedTargetsTest(unittest.TestCase):
    DOMAIN = "unittest-w33-next.local"

    def setUp(self):
        import json

        from burpsuite_mcp.tools.intel._internals import _ensure_dir

        d = _ensure_dir(self.DOMAIN)
        (d / "endpoints.json").write_text(json.dumps({"endpoints": [
            {"url": "/admin/users", "parameters": ["user_id", "q"]},
            {"url": "/static/x", "parameters": ["cachebuster"]},
        ]}))
        (d / "coverage.json").write_text(json.dumps({"entries": []}))

    def tearDown(self):
        from burpsuite_mcp.tools.intel._internals import _intel_path

        shutil.rmtree(_intel_path(self.DOMAIN), ignore_errors=True)

    def _run(self) -> str:
        from burpsuite_mcp.tools.intel import save_load

        fn = _capture(save_load.register)["next_untested_targets"]
        return asyncio.run(fn(self.DOMAIN))

    def test_param_signal_target_ranked_first(self):
        out = self._run()
        # user_id carries an idor param-name signal; it must rank above the
        # signal-less /static/x cachebuster param.
        self.assertIn("user_id", out)
        self.assertIn("param-name signal", out)
        self.assertLess(out.index("/admin/users"), out.index("/static/x"))


# --------------------------------------------------------------------------
# 6. episodes — _redact + record/recall round-trip
# --------------------------------------------------------------------------
class EpisodesTest(unittest.TestCase):
    DOMAIN = "unittest-w33-epi.local"

    def tearDown(self):
        from burpsuite_mcp.tools.intel._internals import _intel_path

        shutil.rmtree(_intel_path(self.DOMAIN), ignore_errors=True)

    def test_redact_strips_credential_shapes(self):
        from burpsuite_mcp.tools.intel.episodes import _redact

        bearer = "authorization: Bearer abc123DEFsecretVALUE"
        self.assertNotIn("abc123DEFsecretVALUE", _redact(bearer))

        jwt = "prefix eyJhbGciOi.eyJzdWIiOm.QsSg0kSig suffix"
        self.assertIn("<redacted-jwt>", _redact(jwt))

        pw = "password=SuperSecretHunter2"
        self.assertNotIn("SuperSecretHunter2", _redact(pw))

    def test_record_recall_round_trip(self):
        from burpsuite_mcp.tools.intel import episodes

        tools = _capture(episodes.register)
        record = tools["record_probe_outcome"]
        recall = tools["recall_probe_outcomes"]

        asyncio.run(record(
            self.DOMAIN,
            action="auto_probe ssti on /render?q",
            target="/render?q",
            outcome="no reflection",
            result="dead_end",
        ))
        out = asyncio.run(recall(self.DOMAIN, query="ssti"))
        self.assertIn("auto_probe ssti", out)
        self.assertIn("dead_end", out)

    def test_recall_redacts_persisted_secret(self):
        from burpsuite_mcp.tools.intel import episodes

        tools = _capture(episodes.register)
        asyncio.run(tools["record_probe_outcome"](
            self.DOMAIN,
            action="replay with Authorization: Bearer leakTOKEN12345",
            target="/api",
            outcome="200",
            result="inconclusive",
        ))
        out = asyncio.run(tools["recall_probe_outcomes"](self.DOMAIN, query="replay"))
        self.assertNotIn("leakTOKEN12345", out)


if __name__ == "__main__":
    unittest.main()
