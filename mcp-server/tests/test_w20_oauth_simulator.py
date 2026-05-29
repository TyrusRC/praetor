"""W20-T1 — oauth_flow_simulator MCP tool tests."""

from __future__ import annotations

import unittest
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


class OAuthFlowHelpersTest(unittest.TestCase):

    def test_gen_state_random(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _gen_state
        s1 = _gen_state()
        s2 = _gen_state()
        self.assertNotEqual(s1, s2)
        self.assertGreater(len(s1), 16)

    def test_gen_pkce_pair_s256(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _gen_pkce_pair
        verifier, challenge = _gen_pkce_pair("S256")
        # S256 base64url SHA-256 yields 43 chars (no padding).
        self.assertEqual(len(challenge), 43)
        self.assertNotEqual(verifier, challenge)

    def test_gen_pkce_pair_plain(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _gen_pkce_pair
        verifier, challenge = _gen_pkce_pair("plain")
        # Plain: challenge == verifier.
        self.assertEqual(verifier, challenge)

    def test_gen_pkce_pair_rejects_unknown(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _gen_pkce_pair
        with self.assertRaises(ValueError):
            _gen_pkce_pair("MD5")

    def test_extract_query_present(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _extract_query
        url = "https://app.example.com/cb?code=abc&state=xyz&foo=bar"
        self.assertEqual(_extract_query(url, "code"), "abc")
        self.assertEqual(_extract_query(url, "state"), "xyz")

    def test_extract_query_missing(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _extract_query
        self.assertEqual(_extract_query("https://x.com/", "code"), "")


class OAuthFlowSimulatorContractTest(unittest.IsolatedAsyncioTestCase):

    async def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        self.assertIn("oauth_flow_simulator", captured)
        sig = captured["oauth_flow_simulator"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    async def test_missing_required_args_error_verdict(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        out = await captured["oauth_flow_simulator"](
            authorize_url="",
            token_url="https://x.com/token",
            client_id="abc",
            redirect_uri="https://app.example.com/cb",
        )
        self.assertEqual(out["verdict"], "ERROR")
        self.assertEqual(out["vuln_type"], "oauth")


class OAuthFlowSimulatorMockedFlowTest(unittest.IsolatedAsyncioTestCase):
    """End-to-end with mocked Burp client. Demonstrates the audit on a
    perfectly-defended IdP — should return FAILED (clean)."""

    async def test_clean_idp_returns_failed_verdict(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        call_log: list[dict] = []

        async def fake_post(path, json=None):
            call_log.append({"path": path, "json": json})
            url = (json or {}).get("url", "")
            # /authorize requests → return redirect with valid code + echoed state
            if "authorize" in url:
                # Echo back the state from the URL.
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                sent_state = qs.get("state", [""])[0]
                # If suffix-bypass redirect_uri requested, reject (strict).
                redirect_uri = qs.get("redirect_uri", [""])[0]
                if "attacker.tld" in redirect_uri:
                    return {
                        "status": 400,
                        "history_index": 1001,
                        "response_headers": [],
                        "response_body": '{"error":"invalid_redirect_uri"}',
                    }
                return {
                    "status": 302,
                    "history_index": 1002,
                    "response_headers": [
                        {"name": "Location",
                         "value": f"https://app.example.com/cb?code=abc123&state={sent_state}"}
                    ],
                    "response_body": "",
                }
            # /token requests → first call succeeds; replay fails (single-use);
            # wrong-verifier call (PKCE check) fails.
            if "token" in url:
                body = (json or {}).get("body", "")
                if "wrong_verifier" in body:
                    return {"status": 400, "history_index": 1003,
                            "response_body": '{"error":"invalid_grant"}'}
                # Track code use — second use of "abc123" fails.
                code_uses = sum(1 for c in call_log if c["json"]
                                 and "abc123" in c["json"].get("body", "")
                                 and "token" in c["json"].get("url", ""))
                if code_uses > 1:
                    return {"status": 400, "history_index": 1004,
                            "response_body": '{"error":"invalid_grant"}'}
                return {"status": 200, "history_index": 1005,
                        "response_body": '{"access_token":"tok","token_type":"Bearer"}'}
            return {"error": f"unhandled mock url: {url}"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)

        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_flow_simulator"](
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                client_id="praetor-test-client",
                redirect_uri="https://app.example.com/cb",
                scope="openid profile",
            )

        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["vuln_type"], "oauth")
        # Mock IdP echoes state, single-use code, validates PKCE, strict
        # redirect_uri — zero defects.
        self.assertEqual(len(out["details"]["defects"]), 0)
        # PKCE was attempted.
        self.assertTrue(out["details"]["pkce_used"])

    async def test_redirect_uri_bypass_detected(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if "authorize" in url:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                sent_state = qs.get("state", [""])[0]
                redirect_uri = qs.get("redirect_uri", [""])[0]
                # Sloppy IdP — accepts ANY redirect_uri including attacker suffix.
                return {
                    "status": 302,
                    "history_index": 2001,
                    "response_headers": [
                        {"name": "Location",
                         "value": f"{redirect_uri}?code=xyz&state={sent_state}"}
                    ],
                    "response_body": "",
                }
            if "token" in url:
                return {"status": 200, "history_index": 2002,
                        "response_body": '{"access_token":"tok"}'}
            return {"error": "unhandled"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)

        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_flow_simulator"](
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                client_id="test",
                redirect_uri="https://app.example.com/cb",
                scope="openid",
                skip_pkce=True,
            )

        # Expect SUSPECTED or CONFIRMED — redirect_uri_suffix_bypass is critical class.
        self.assertIn(out["verdict"], ("SUSPECTED", "CONFIRMED"))
        defect_names = " ".join(out["details"]["defects"])
        self.assertIn("redirect_uri_suffix_bypass", defect_names)


if __name__ == "__main__":
    unittest.main()
