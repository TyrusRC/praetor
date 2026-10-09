"""Decision engine (_decision) + decision_tools — tiered backend, Jev request
shape, LLM-JSON fallback, off-tier degrade. All patched globals are restored."""

import asyncio
import os
import unittest

import httpx

from praetor.tools import _decision as D
from praetor.tools import _llm
from praetor.tools import decision_tools as DT


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


_ENV = ("PRAETOR_DECISION_PROVIDER", "AI_GATEWAY_API_KEY", "PRAETOR_DECISION_API_KEY",
        "PRAETOR_DECISION_MODEL", "PRAETOR_DECISION_BASE_URL")


class DecisionBase(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV}
        for k in _ENV:
            os.environ.pop(k, None)
        self._saved_httpx = httpx.AsyncClient
        self._saved_llm = (_llm.resolve_llm, _llm.complete)

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        httpx.AsyncClient = self._saved_httpx
        _llm.resolve_llm, _llm.complete = self._saved_llm

    def _mock_jev(self, answers):
        captured = {}

        class _Resp:
            def raise_for_status(self): pass
            def json(self): return {"answers": answers}

        class _Cli:
            def __init__(s, **k): pass
            async def __aenter__(s): return s
            async def __aexit__(s, *a): return False
            async def post(s, url, headers, json):
                captured["url"] = url
                captured["headers"] = headers
                captured["body"] = json
                return _Resp()

        httpx.AsyncClient = _Cli
        return captured


class ResolveTest(DecisionBase):
    def test_off_when_nothing_configured(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": False})()
        self.assertEqual(D.resolve_decision().tier, "off")
        self.assertFalse(D.available())

    def test_jev_when_gateway_key(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        cfg = D.resolve_decision()
        self.assertEqual(cfg.tier, "jev")
        self.assertEqual(cfg.model, "typesafe-ai/jev")

    def test_forced_jev_without_key_or_local_is_off(self):
        os.environ["PRAETOR_DECISION_PROVIDER"] = "jev"
        self.assertEqual(D.resolve_decision().tier, "off")

    def test_local_engine_selects_jev_keyless(self):
        # self-hosted Haruspex on loopback — no key, picked automatically
        os.environ["PRAETOR_DECISION_BASE_URL"] = "http://127.0.0.1:3000"
        cfg = D.resolve_decision()
        self.assertEqual(cfg.tier, "jev")
        self.assertEqual(cfg.api_key, "")
        self.assertTrue(D.available(cfg))

    def test_llm_tier_when_llm_ok(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": True})()
        os.environ["PRAETOR_DECISION_PROVIDER"] = "llm"
        self.assertEqual(D.resolve_decision().tier, "llm")


class JevShapeTest(DecisionBase):
    def test_jev_request_and_rank(self):
        os.environ["AI_GATEWAY_API_KEY"] = "secret"
        cap = self._mock_jev({"q0": {"type": "boolean", "probability": 0.9},
                              "q1": {"type": "boolean", "probability": 0.1}})
        items = [{"key": "a", "state": "wordpress"}, {"key": "b", "state": "iis"}]
        ranked = asyncio.run(D.rank_relevant("WordPress target", items))
        self.assertEqual([r["key"] for r in ranked], ["a", "b"])   # sorted by prob desc
        self.assertEqual(ranked[0]["relevance"], 0.9)
        self.assertTrue(cap["url"].endswith("/v1/evaluate"))
        self.assertEqual(cap["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(cap["body"]["model"], "typesafe-ai/jev")
        self.assertEqual(len(cap["body"]["questions"]), 2)        # one round trip

    def test_hosted_jev_sends_auth_header(self):
        os.environ["AI_GATEWAY_API_KEY"] = "hk"
        cap = self._mock_jev({"q0": {"type": "boolean", "probability": 0.5}})
        asyncio.run(D.rank_relevant("t", [{"key": "a", "state": "x"}]))
        self.assertEqual(cap["headers"].get("Authorization"), "Bearer hk")

    def test_local_jev_omits_auth_header(self):
        os.environ["PRAETOR_DECISION_BASE_URL"] = "http://127.0.0.1:3000"  # keyless local
        cap = self._mock_jev({"q0": {"type": "boolean", "probability": 0.5}})
        asyncio.run(D.rank_relevant("t", [{"key": "a", "state": "x"}]))
        self.assertNotIn("Authorization", cap["headers"])

    def test_jev_choice_passthrough(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        self._mock_jev({"sev": {"type": "choice", "choice": "high",
                                "probabilities": {"high": 0.8, "low": 0.2}}})
        ans = asyncio.run(D.evaluate("a finding", {"sev": {"type": "choice",
              "instructions": "severity?", "criteria": {"high": "", "low": ""}}}))
        self.assertEqual(ans["sev"]["choice"], "high")


class LlmTierTest(DecisionBase):
    def test_llm_json_answers(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": True})()

        async def fake_complete(prompt, **kw):
            return '{"q0": {"probability": 0.7}}'
        _llm.complete = fake_complete
        os.environ["PRAETOR_DECISION_PROVIDER"] = "llm"
        ans = asyncio.run(D.evaluate("state", {"q0": {"type": "boolean", "instructions": "x?"}}))
        self.assertEqual(ans["q0"]["probability"], 0.7)


class ToolsTest(DecisionBase):
    def setUp(self):
        super().setUp()
        self.mcp = _FakeMCP()
        DT.register(self.mcp)

    def _call(self, name, **kw):
        return asyncio.run(self.mcp.tools[name](**kw))

    def test_status_off(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": False})()
        out = self._call("decision_status")
        self.assertEqual(out["tier"], "off")
        self.assertFalse(out["available"])

    def test_relevance_off_keeps_order(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": False})()
        items = [{"key": "a", "state": "x"}, {"key": "b", "state": "y"}]
        out = self._call("decide_relevance", state="t", items=items)
        self.assertFalse(out["available"])
        self.assertEqual(out["ranked"], items)   # unchanged, no regression

    def test_relevance_accepts_json_string(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        self._mock_jev({"q0": {"type": "boolean", "probability": 0.5}})
        out = self._call("decide_relevance", state="t", items='[{"key":"a","state":"x"}]')
        self.assertTrue(out["available"])
        self.assertEqual(out["ranked"][0]["key"], "a")

    def test_questions_requires_input(self):
        self.assertIn("questions must", self._call("decide_questions", state="s")["error"])


if __name__ == "__main__":
    unittest.main()
