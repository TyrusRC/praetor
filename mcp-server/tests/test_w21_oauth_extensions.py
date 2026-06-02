"""W21-T1 — oauth_device_flow_simulator + oauth_hybrid_flow_simulator
+ oauth_dpop_audit tests."""

from __future__ import annotations

import base64
import hashlib
import json
import time
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


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict, claims: dict) -> str:
    h = _b64url_nopad(json.dumps(header, separators=(",", ":")).encode())
    c = _b64url_nopad(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{c}.sig"


class OAuthHelpersExtTest(unittest.TestCase):

    def test_jwt_decode_unverified(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _jwt_decode_unverified
        tok = _make_jwt({"alg": "RS256"}, {"sub": "abc", "nonce": "xyz"})
        h, c, _ = _jwt_decode_unverified(tok)
        self.assertEqual(h["alg"], "RS256")
        self.assertEqual(c["nonce"], "xyz")

    def test_jwt_decode_rejects_malformed(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _jwt_decode_unverified
        with self.assertRaises(ValueError):
            _jwt_decode_unverified("not.a-jwt")

    def test_extract_fragment(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _extract_fragment
        url = "https://app.example.com/cb#code=abc&id_token=eyJ&state=s1"
        self.assertEqual(_extract_fragment(url, "code"), "abc")
        self.assertEqual(_extract_fragment(url, "id_token"), "eyJ")
        self.assertEqual(_extract_fragment(url, "missing"), "")

    def test_at_hash_match(self):
        from burpsuite_mcp.tools.auth.oauth_flow import _at_hash_match
        at = "access_token_value"
        digest = hashlib.sha256(at.encode()).digest()
        good = _b64url_nopad(digest[: len(digest) // 2])
        self.assertTrue(_at_hash_match(at, good))
        self.assertFalse(_at_hash_match(at, "definitely_wrong"))


class DeviceFlowSimulatorTest(unittest.IsolatedAsyncioTestCase):

    async def test_clean_idp_failed_verdict(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if "device_authorization" in url:
                return {
                    "status": 200, "history_index": 4001,
                    "response_body": json_dumps({
                        "device_code": "dev-abc",
                        "user_code": "WDJB-MJHT",  # high-entropy 8 unique chars
                        "verification_uri": "https://idp.example.com/device",
                        "verification_uri_complete": "https://idp.example.com/device?u=WDJB-MJHT",
                        "interval": 5, "expires_in": 600,
                    }),
                }
            if "token" in url:
                # Clean IdP: first poll authorization_pending, second slow_down.
                body = (json or {}).get("body", "")
                if "device_code=dev-abc" not in body:
                    return {"status": 400, "history_index": 4002,
                            "response_body": json_dumps({"error": "invalid_request"})}
                # Track call order via mutable counter on the closure.
                fake_post.poll_count = getattr(fake_post, "poll_count", 0) + 1
                if fake_post.poll_count == 1:
                    return {"status": 400, "history_index": 4003,
                            "response_body": json_dumps({"error": "authorization_pending"})}
                return {"status": 400, "history_index": 4004,
                        "response_body": json_dumps({"error": "slow_down"})}
            return {"error": "unhandled"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_device_flow_simulator"](
                device_authorization_url="https://idp.example.com/device_authorization",
                token_url="https://idp.example.com/token",
                client_id="praetor-device",
            )
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["defects"], [])

    async def test_low_entropy_user_code_flagged(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if "device_authorization" in url:
                return {
                    "status": 200, "history_index": 4101,
                    "response_body": json_dumps({
                        "device_code": "dev-xyz",
                        "user_code": "AAAA",  # 4 chars, 1 unique = ~0 bits
                        "verification_uri": "https://idp.example.com/d",
                        "interval": 5, "expires_in": 600,
                    }),
                }
            if "token" in url:
                return {"status": 400, "history_index": 4102,
                        "response_body": json_dumps({"error": "slow_down"})}
            return {"error": "unhandled"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_device_flow_simulator"](
                device_authorization_url="https://idp.example.com/device_authorization",
                token_url="https://idp.example.com/token",
                client_id="praetor-device",
            )
        defects = " ".join(out["details"]["defects"])
        self.assertIn("user_code_low_entropy", defects)


class HybridFlowSimulatorTest(unittest.IsolatedAsyncioTestCase):

    async def test_clean_hybrid_returns_failed(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        # Build a clean id_token with proper at_hash + nonce echo.
        nonce_holder: dict = {}

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if "authorize" in url:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                sent_state = qs.get("state", [""])[0]
                sent_nonce = qs.get("nonce", [""])[0]
                nonce_holder["v"] = sent_nonce
                access_token = "atk_clean"
                digest = hashlib.sha256(access_token.encode()).digest()
                at_hash = _b64url_nopad(digest[: len(digest) // 2])
                id_token = _make_jwt(
                    {"alg": "RS256"},
                    {"sub": "user1", "nonce": sent_nonce, "at_hash": at_hash},
                )
                loc = (
                    f"https://app.example.com/cb#code=hyc&state={sent_state}"
                    f"&id_token={id_token}&access_token={access_token}"
                )
                return {
                    "status": 302, "history_index": 5001,
                    "response_headers": [{"name": "Location", "value": loc}],
                    "response_body": "",
                }
            return {"error": "unhandled"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_hybrid_flow_simulator"](
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                client_id="hybrid-client",
                redirect_uri="https://app.example.com/cb",
            )
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["defects"], [])

    async def test_alg_none_and_nonce_mismatch_detected(self):
        from burpsuite_mcp.tools.auth import oauth_flow

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if "authorize" in url:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                sent_state = qs.get("state", [""])[0]
                # Issuer ignores nonce + signs with alg=none — two critical defects.
                id_token = _make_jwt(
                    {"alg": "none"},
                    {"sub": "user1", "nonce": "WRONG_NONCE"},
                )
                loc = (
                    f"https://app.example.com/cb#code=x&state={sent_state}"
                    f"&id_token={id_token}"
                )
                return {
                    "status": 302, "history_index": 5101,
                    "response_headers": [{"name": "Location", "value": loc}],
                    "response_body": "",
                }
            return {"error": "unhandled"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_hybrid_flow_simulator"](
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                client_id="bad-hybrid",
                redirect_uri="https://app.example.com/cb",
            )
        self.assertEqual(out["verdict"], "CONFIRMED")
        defects = " ".join(out["details"]["defects"])
        self.assertIn("id_token_alg_none", defects)
        self.assertIn("nonce_not_bound", defects)

    async def test_response_type_validation(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        out = await captured["oauth_hybrid_flow_simulator"](
            authorize_url="https://idp.example.com/authorize",
            token_url="https://idp.example.com/token",
            client_id="x",
            redirect_uri="https://app.example.com/cb",
            response_type="code",  # not hybrid
        )
        self.assertEqual(out["verdict"], "ERROR")


class DpopAuditTest(unittest.IsolatedAsyncioTestCase):

    def _make_proof(self, htu: str, htm: str = "GET", iat: int | None = None) -> str:
        return _make_jwt(
            {"alg": "ES256", "typ": "dpop+jwt", "jwk": {
                "kty": "EC", "crv": "P-256", "x": "abc", "y": "def",
            }},
            {"htu": htu, "htm": htm, "iat": iat if iat is not None else int(time.time()),
             "jti": "j1"},
        )

    async def test_htu_enforced_failed(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        proof = self._make_proof("https://api.example.com/me")
        access_token = "opaque_token"

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            # Strict resource — reject mismatched htu.
            if url == "https://api.example.com/me":
                return {"status": 200, "history_index": 6001, "response_body": "{}"}
            return {"status": 401, "history_index": 6002,
                    "response_body": '{"error":"invalid_dpop_proof"}'}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_dpop_audit"](
                access_token=access_token, dpop_proof=proof,
                resource_urls=[
                    "https://api.example.com/me",
                    "https://api.example.com/admin",
                ],
            )
        self.assertEqual(out["verdict"], "FAILED")

    async def test_htu_reuse_detected(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        proof = self._make_proof("https://api.example.com/me")

        async def fake_post(path, json=None):
            # Sloppy resource — accepts proof regardless of htu.
            return {"status": 200, "history_index": 6101, "response_body": "{}"}

        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        with patch.object(oauth_flow.client, "post", side_effect=fake_post):
            out = await captured["oauth_dpop_audit"](
                access_token="opaque",
                dpop_proof=proof,
                resource_urls=[
                    "https://api.example.com/me",
                    "https://api.example.com/admin",
                    "https://api.example.com/billing",
                ],
            )
        self.assertIn(out["verdict"], ("SUSPECTED", "CONFIRMED"))
        self.assertIn("dpop_htu_not_enforced",
                      " ".join(out["details"]["defects"]))
        self.assertEqual(len(out["details"]["accepted_mismatch"]), 2)

    async def test_missing_resources(self):
        from burpsuite_mcp.tools.auth import oauth_flow
        stub, captured = _stub_mcp()
        oauth_flow.register(stub)
        out = await captured["oauth_dpop_audit"](
            access_token="x", dpop_proof=self._make_proof("https://a/"),
            resource_urls=[],
        )
        self.assertEqual(out["verdict"], "ERROR")


def json_dumps(d: dict) -> str:
    """Local stdlib alias — pure stdlib JSON without leak into other namespaces."""
    return json.dumps(d)


if __name__ == "__main__":
    unittest.main()
