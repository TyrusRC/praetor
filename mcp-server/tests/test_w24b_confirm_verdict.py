"""W24-b — verdict refactor wave 2: confirm_sqli / confirm_ssti / confirm_ssrf /
confirm_xxe / confirm_rce migrated from string-return to W7 VerdictResult dict."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.testing._verdict import is_actionable, to_assess_evidence


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


# ────────────────────────────────────────────────────────────────────
# confirm_sqli
# ────────────────────────────────────────────────────────────────────
class ConfirmSqliVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_unknown_dbms_error(self):
        fn = _tool("confirm_sqli")
        out = await fn(endpoint="https://t/x", parameter="id", dbms="oracle9")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertEqual(out["vuln_type"], "sqli")

    async def test_unknown_strategy_error(self):
        fn = _tool("confirm_sqli")
        out = await fn(endpoint="https://t/x", parameter="id", strategy="blind")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_marker_hit_confirmed(self):
        # Server response echoes M-<marker>
        async def fake_post(path, json=None):
            return {
                "response_body": "result: M-deadbeef appears here",
                "status_code": 200,
                "proxy_index": 42,
            }
        with patch("burpsuite_mcp.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_sqli.make_marker",
                   return_value="m-deadbeef"):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id",
                           dbms="mysql", strategy="union")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertIn(42, out["logger_indices"])
        self.assertTrue(is_actionable(out))

    async def test_no_marker_failed(self):
        async def fake_post(path, json=None):
            return {"response_body": "no marker here", "status_code": 200,
                    "proxy_index": 7}
        with patch("burpsuite_mcp.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertFalse(is_actionable(out))

    async def test_timing_strategy_fires_three_replays_and_populates_reproductions(self):
        """Rule 10a: sqli_time needs ≥3 reproductions in reproductions[].
        confirm_sqli strategy='time' must fire 3 sends, capture elapsed_ms
        per send, and only CONFIRM when ALL 3 clear the 4.5s floor."""
        # Force three slow sends — patch time.monotonic to fake 5s elapsed
        responses = iter([
            {"response_body": "", "status_code": 200, "proxy_index": 100},
            {"response_body": "", "status_code": 200, "proxy_index": 101},
            {"response_body": "", "status_code": 200, "proxy_index": 102},
        ])
        # Patch monotonic to return alternating values producing ~5s each
        ticks = iter([0.0, 5.1, 5.1, 10.2, 10.2, 15.3])

        def fake_monotonic():
            return next(ticks)

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_sqli.time.monotonic",
                   side_effect=fake_monotonic):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id",
                           dbms="mysql", strategy="time")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["vuln_type"], "sqli_time")
        self.assertEqual(len(out["reproductions"]), 3)
        for r in out["reproductions"]:
            self.assertGreaterEqual(r["elapsed_ms"], 4500)
        # all three logger indices captured
        self.assertEqual(sorted(out["logger_indices"]), [100, 101, 102])

    async def test_timing_inconsistent_fails(self):
        """If only some samples clear 4.5s, verdict is FAILED — operator
        re-tries rather than reporting a flaky timing finding."""
        responses = iter([
            {"response_body": "", "status_code": 200, "proxy_index": 200},
            {"response_body": "", "status_code": 200, "proxy_index": 201},
            {"response_body": "", "status_code": 200, "proxy_index": 202},
        ])
        # 5s, 0.5s, 5s — one fast, two slow → inconsistent → FAILED
        ticks = iter([0.0, 5.1, 5.1, 5.6, 5.6, 10.7])

        def fake_monotonic():
            return next(ticks)

        async def fake_post(path, json=None):
            return next(responses)

        with patch("burpsuite_mcp.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_sqli.time.monotonic",
                   side_effect=fake_monotonic):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id",
                           strategy="time")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(len(out["reproductions"]), 3)


# ────────────────────────────────────────────────────────────────────
# confirm_ssti
# ────────────────────────────────────────────────────────────────────
class ConfirmSstiVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_unknown_engine_error(self):
        fn = _tool("confirm_ssti")
        out = await fn(endpoint="https://t/x", parameter="q", engine="rubytmpl")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_custom_payload_needs_expected(self):
        fn = _tool("confirm_ssti")
        out = await fn(endpoint="https://t/x", parameter="q",
                       custom_payload="${1+1}")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("custom_expected", out["evidence_summary"])

    async def test_engine_match_confirmed(self):
        # Response contains "392" (the freemarker expected)
        async def fake_post(path, json=None):
            return {"response_body": "user submitted: 392", "status_code": 200,
                    "proxy_index": 11}
        with patch("burpsuite_mcp.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="freemarker")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["matched_engine"], "freemarker")

    async def test_no_match_failed(self):
        async def fake_post(path, json=None):
            return {"response_body": "no rendering here", "status_code": 200,
                    "proxy_index": 3}
        with patch("burpsuite_mcp.tools.exploit.confirm_ssti.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssti")
            out = await fn(endpoint="https://t/x", parameter="q", engine="freemarker")
        self.assertEqual(out["verdict"], "FAILED")


# ────────────────────────────────────────────────────────────────────
# confirm_ssrf
# ────────────────────────────────────────────────────────────────────
class ConfirmSsrfVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_collaborator_unavailable_error(self):
        async def fake_post(path, json=None):
            if path == "/api/collaborator/payload":
                return {"error": "Community edition"}
            return {}
        with patch("burpsuite_mcp.tools.exploit.confirm_ssrf.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_ssrf")
            out = await fn(endpoint="https://t/fetch", parameter="url")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("Community", out["evidence_summary"])

    async def test_callback_confirmed(self):
        post_responses = iter([
            {"payload": "xyz.oastify.com"},  # collaborator alloc
            *[{"proxy_index": 5 + i, "status_code": 500} for i in range(6)],  # probes
        ])

        async def fake_post(path, json=None):
            return next(post_responses)

        async def fake_get(path):
            # SSRF marker uses prefix='ssrf' + hex
            return {"interactions": [{"type": "DNS", "payload_id": "abc123",
                                       "raw": "ssrf-deadbeef.xyz.oastify.com"}]}

        # Force the marker so we can ensure poll matches
        with patch("burpsuite_mcp.tools.exploit.confirm_ssrf.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_ssrf.client.get",
                   new=AsyncMock(side_effect=fake_get)), \
             patch("burpsuite_mcp.tools.exploit.confirm_ssrf.make_marker",
                   return_value="ssrf-deadbeef"), \
             patch("burpsuite_mcp.tools.exploit.confirm_ssrf.asyncio.sleep",
                   new=AsyncMock(return_value=None)):
            fn = _tool("confirm_ssrf")
            out = await fn(endpoint="https://t/fetch", parameter="url",
                           poll_seconds=1)
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertIn("abc123", out["collaborator_interactions"])
        ev = to_assess_evidence(out)
        self.assertEqual(ev["collaborator_interaction_id"], "abc123")

    async def test_no_callback_failed(self):
        post_responses = iter([
            {"payload": "xyz.oastify.com"},
            *[{"proxy_index": 10 + i, "status_code": 200} for i in range(6)],
        ])

        async def fake_post(path, json=None):
            return next(post_responses)

        async def fake_get(path):
            return {"interactions": []}

        with patch("burpsuite_mcp.tools.exploit.confirm_ssrf.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_ssrf.client.get",
                   new=AsyncMock(side_effect=fake_get)), \
             patch("burpsuite_mcp.tools.exploit.confirm_ssrf.asyncio.sleep",
                   new=AsyncMock(return_value=None)):
            fn = _tool("confirm_ssrf")
            out = await fn(endpoint="https://t/fetch", parameter="url", poll_seconds=1)
        self.assertEqual(out["verdict"], "FAILED")


# ────────────────────────────────────────────────────────────────────
# confirm_xxe
# ────────────────────────────────────────────────────────────────────
class ConfirmXxeVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_unknown_mode_error(self):
        fn = _tool("confirm_xxe")
        out = await fn(endpoint="https://t/x", mode="hybrid")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_inband_hostname_extracted_confirmed(self):
        # Parser greps lines that look like file content; a bare hostname-style
        # line (alphanum + -_.) qualifies. Build a response where the entity
        # expansion yields exactly such a line.
        async def fake_post(path, json=None):
            return {
                "response_body": "Result:\nsomehostname\nthat is the host",
                "status_code": 200,
                "proxy_index": 99,
            }
        with patch("burpsuite_mcp.tools.exploit.confirm_xxe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_xxe")
            out = await fn(endpoint="https://t/xml", mode="inband")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["mode"], "inband")

    async def test_inband_no_extract_failed(self):
        async def fake_post(path, json=None):
            return {"response_body": "<r></r>", "status_code": 200, "proxy_index": 1}
        with patch("burpsuite_mcp.tools.exploit.confirm_xxe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_xxe")
            out = await fn(endpoint="https://t/xml", mode="inband")
        self.assertEqual(out["verdict"], "FAILED")


# ────────────────────────────────────────────────────────────────────
# confirm_rce
# ────────────────────────────────────────────────────────────────────
class ConfirmRceVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_unknown_os_error(self):
        fn = _tool("confirm_rce")
        out = await fn(endpoint="https://t/x", parameter="cmd", os="bsd")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_quiet_gate_blocks_dangerous_cmd(self):
        fn = _tool("confirm_rce")
        out = await fn(endpoint="https://t/x", parameter="cmd",
                       command="cat /etc/shadow", allow_loud=False)
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("REFUSED", out["evidence_summary"])

    async def test_wrapper_out_of_range_error(self):
        fn = _tool("confirm_rce")
        out = await fn(endpoint="https://t/x", parameter="cmd", wrapper_index=99)
        self.assertEqual(out["verdict"], "ERROR")

    async def test_marker_extracted_confirmed(self):
        # Response body contains start + end markers
        async def fake_post(path, json=None):
            body = "junk before M-deadbeef-START\nuid=1000(testuser)\nM-deadbeef-END more junk"
            return {"response_body": body, "status_code": 200, "proxy_index": 77}

        with patch("burpsuite_mcp.tools.exploit.confirm_rce.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.confirm_rce.make_marker",
                   return_value="m-deadbeef"):
            fn = _tool("confirm_rce")
            out = await fn(endpoint="https://t/x", parameter="cmd",
                           command="id", os="linux", wrapper_index=0)
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertIn(77, out["logger_indices"])
        self.assertIn("uid=1000", out["details"]["extracted"])

    async def test_no_marker_failed(self):
        async def fake_post(path, json=None):
            return {"response_body": "no marker here", "status_code": 200,
                    "proxy_index": 5}
        with patch("burpsuite_mcp.tools.exploit.confirm_rce.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("confirm_rce")
            out = await fn(endpoint="https://t/x", parameter="cmd")
        self.assertEqual(out["verdict"], "FAILED")


# ────────────────────────────────────────────────────────────────────
# Registration
# ────────────────────────────────────────────────────────────────────
class RegistrationTest(unittest.TestCase):

    def test_all_five_confirm_tools_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        for required in ("confirm_sqli", "confirm_ssti", "confirm_ssrf",
                         "confirm_xxe", "confirm_rce"):
            self.assertIn(required, names)


class PickToolRoutesConfirmStarTest(unittest.IsolatedAsyncioTestCase):
    """Verb-led 'confirm X' queries must route to confirm_X (and beat the
    bare-noun routes like 'sqli' → auto_probe). Without explicit routing,
    Claude reaches for auto_probe or crafts fresh payloads, defeating the
    point of these audited exploit-confirmation tools."""

    async def _route(self, query):
        from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl
        return await pick_tool_impl(query)

    async def test_routes_confirm_sqli(self):
        out = await self._route("confirm sqli on /login")
        self.assertIn("confirm_sqli", out)

    async def test_routes_confirm_ssrf(self):
        out = await self._route("prove ssrf via collaborator")
        self.assertIn("confirm_ssrf", out)

    async def test_routes_confirm_rce(self):
        out = await self._route("prove rce via cmd parameter")
        self.assertIn("confirm_rce", out)

    async def test_routes_confirm_xxe(self):
        out = await self._route("confirm xxe file read")
        self.assertIn("confirm_xxe", out)

    async def test_routes_confirm_ssti(self):
        out = await self._route("confirm ssti math reflection")
        self.assertIn("confirm_ssti", out)

    async def test_bare_sqli_still_hits_auto_probe(self):
        out = await self._route("scan target for sqli")
        self.assertIn("auto_probe", out)


if __name__ == "__main__":
    unittest.main()
