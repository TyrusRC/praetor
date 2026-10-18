"""enrich_with_haruspex: fail-open Haruspex second opinion on a verdict dict.

Mirrors test_decision.py's mocking pattern. Confirms: backend off -> unchanged,
a transport error -> unchanged, no opinion (nil probability) -> unchanged,
a real answer -> additive `verdict["haruspex"]` only (verdict/confidence untouched)."""

import asyncio
import os
import unittest

import httpx

from praetor.tools import _decision as D
from praetor.tools import _llm
from praetor.tools.testing._verdict import enrich_with_haruspex, make_verdict

_ENV = ("PRAETOR_DECISION_PROVIDER", "AI_GATEWAY_API_KEY", "PRAETOR_DECISION_API_KEY",
        "PRAETOR_DECISION_MODEL", "PRAETOR_DECISION_BASE_URL")


class _Base(unittest.TestCase):
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
                captured["body"] = json
                return _Resp()

        httpx.AsyncClient = _Cli
        return captured

    def _mock_jev_raises(self, exc):
        class _Cli:
            def __init__(s, **k): pass
            async def __aenter__(s): return s
            async def __aexit__(s, *a): return False
            async def post(s, *a, **k): raise exc

        httpx.AsyncClient = _Cli


class EnrichTest(_Base):
    def _verdict(self):
        return make_verdict("CONFIRMED", 0.85, "deterministic evidence", vuln_type="exposure")

    def test_backend_off_leaves_verdict_unchanged(self):
        _llm.resolve_llm = lambda *a, **k: type("C", (), {"ok": False})()
        v = self._verdict()
        out = asyncio.run(enrich_with_haruspex(v, "some finding text"))
        self.assertEqual(out, v)
        self.assertNotIn("haruspex", out)

    def test_transport_error_leaves_verdict_unchanged(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        self._mock_jev_raises(httpx.ConnectError("refused"))
        v = self._verdict()
        out = asyncio.run(enrich_with_haruspex(v, "some finding text"))
        self.assertEqual(out, v)
        self.assertNotIn("haruspex", out)

    def test_no_opinion_leaves_verdict_unchanged(self):
        # e.g. the CVE/cloud router deferred -> no "probability" key
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        self._mock_jev({"q": {"type": "boolean", "label": None, "accept": False, "abstain": True}})
        v = self._verdict()
        out = asyncio.run(enrich_with_haruspex(v, "ambiguous text"))
        self.assertEqual(out, v)
        self.assertNotIn("haruspex", out)

    def test_real_answer_is_additive_only(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        cap = self._mock_jev({"q": {"type": "boolean", "probability": 0.93,
                                    "domain_source": "hint", "source": "model"}})
        v = self._verdict()
        out = asyncio.run(enrich_with_haruspex(v, "a sourcemap exposes production API keys", domain="web"))
        # original verdict fields untouched
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["confidence"], 0.85)
        self.assertEqual(out["evidence_summary"], "deterministic evidence")
        # second opinion layered on, additively
        self.assertEqual(out["haruspex"], {"probability": 0.93, "domain": "web",
                                           "domain_source": "hint", "source": "model"})
        self.assertEqual(cap["body"]["domain"], "web")

    def test_domain_is_threaded_to_the_request(self):
        os.environ["AI_GATEWAY_API_KEY"] = "k"
        cap = self._mock_jev({"q": {"type": "boolean", "probability": 0.1}})
        v = self._verdict()
        asyncio.run(enrich_with_haruspex(v, "x", domain="network"))
        self.assertEqual(cap["body"]["domain"], "network")


if __name__ == "__main__":
    unittest.main()
