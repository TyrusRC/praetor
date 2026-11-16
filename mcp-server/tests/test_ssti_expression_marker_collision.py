"""Regression: confirm_ssti / confirm_expression used 2-digit math markers
(7*7->49, django 7|add:7->14, node/python/ruby 7*7->49) that collide with an
ordinary page number (price, count, timestamp) and would false-positive a
template/expression-injection CONFIRMED verdict with no payload ever reaching
the engine. confirm_expression's detect phase additionally had no reflection
guard at all (confirm_ssti already had one). Fixed to the project's existing
"392" convention (7*7*8 or an equivalent per-engine construction) and added
the missing guard. Found by comparing against CyberStrike's Vortex canary
design (two random factors, product as the marker, specifically to avoid
this exact collision class).
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from praetor import server


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class SstiMarkerCollisionTest(unittest.IsolatedAsyncioTestCase):

    async def test_jinja2_math_no_longer_uses_56(self):
        """A page that naturally contains "56" (e.g. a price or count) must
        not confirm jinja2_math — the distinguisher is now 392 (7*8*7)."""
        async def fake_post(path, json=None):
            return {"response_body": "items: 56 in stock", "status_code": 200,
                    "proxy_index": 1}
        with patch("praetor.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="jinja2_math")
        self.assertEqual(out["verdict"], "FAILED")

    async def test_django_no_longer_uses_14(self):
        """A page that naturally contains "14" must not confirm django."""
        async def fake_post(path, json=None):
            return {"response_body": "page 14 of 20", "status_code": 200,
                    "proxy_index": 2}
        with patch("praetor.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="django")
        self.assertEqual(out["verdict"], "FAILED")

    async def test_twig_no_longer_uses_49(self):
        """A page that naturally contains "49" must not confirm twig."""
        async def fake_post(path, json=None):
            return {"response_body": "error code 49 returned", "status_code": 200,
                    "proxy_index": 3}
        with patch("praetor.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="twig")
        self.assertEqual(out["verdict"], "FAILED")

    async def test_twig_still_confirms_on_real_evaluation(self):
        """392 present, raw payload absent -> still confirms (fix did not
        just break detection, it closed the collision)."""
        async def fake_post(path, json=None):
            return {"response_body": "result: 392", "status_code": 200,
                    "proxy_index": 4}
        with patch("praetor.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="twig")
        self.assertEqual(out["verdict"], "CONFIRMED")

    async def test_no_weak_markers_remain_in_the_probe_table(self):
        from praetor.tools.exploit.confirm_ssti import _TEMPLATE_PROBES
        weak = {"49", "14", "56", "7"}
        hits = [(eng, exp) for eng, _payload, exp in _TEMPLATE_PROBES if exp in weak]
        self.assertEqual(hits, [], f"collision-prone markers still present: {hits}")


class ExpressionMarkerCollisionTest(unittest.IsolatedAsyncioTestCase):

    async def test_python_eval_no_longer_uses_49(self):
        """A page that naturally contains "49" must not confirm python_eval —
        confirm_expression had NO reflection guard at all before this fix."""
        async def fake_post(path, json=None):
            return {"response_body": "HTTP 49 custom status", "status_code": 200,
                    "proxy_index": 5}
        with patch("praetor.tools.exploit.confirm_expression.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_expression")
            out = await fn(endpoint="https://t/x", parameter="q", language="python_eval")
        self.assertEqual(out["verdict"], "FAILED")

    async def test_python_eval_still_confirms_on_real_evaluation(self):
        async def fake_post(path, json=None):
            return {"response_body": "computed=392", "status_code": 200,
                    "proxy_index": 6}
        with patch("praetor.tools.exploit.confirm_expression.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_expression")
            out = await fn(endpoint="https://t/x", parameter="q", language="python_eval")
        self.assertEqual(out["verdict"], "CONFIRMED")

    async def test_reflection_guard_rejects_literal_echo(self):
        """The raw payload text reflected verbatim (unevaluated) must not
        count as a hit even if the expected substring happens to also be
        present elsewhere in that same echoed text."""
        async def fake_post(path, json=None):
            return {"response_body": "you searched for: 7*7*8 (392 results tag not evaluated)",
                    "status_code": 200, "proxy_index": 7}
        with patch("praetor.tools.exploit.confirm_expression.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_expression")
            out = await fn(endpoint="https://t/x", parameter="q", language="python_eval")
        self.assertEqual(out["verdict"], "FAILED")

    async def test_no_weak_markers_remain_in_the_probe_table(self):
        from praetor.tools.exploit.confirm_expression import _PROBES
        weak = {"49", "14", "56", "7"}
        hits = [(lang, phase, exp) for lang, phase, _payload, exp in _PROBES
                if phase == "detect" and exp in weak]
        self.assertEqual(hits, [], f"collision-prone markers still present: {hits}")


if __name__ == "__main__":
    unittest.main()
