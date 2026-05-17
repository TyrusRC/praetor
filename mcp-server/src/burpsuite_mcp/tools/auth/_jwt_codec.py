"""Shared JWT codec helpers — split out so forge / crack / analyze stay short.

All base64url helpers tolerate missing padding (real-world JWTs strip `=`).
Sign helpers cover HS256/384/512 (stdlib) + RS256/384/512 (cryptography).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def b64url_decode(s: str) -> bytes:
    """Pad-tolerant urlsafe base64 decode."""
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def b64url_encode(data: bytes) -> str:
    """Urlsafe base64 encode without padding (JWT spec)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def split_jwt(token: str) -> tuple[str, str, str]:
    """Split into (header_b64, payload_b64, signature_b64). Raises ValueError."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"invalid JWT format: expected 3 parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]


def decode_header(token: str) -> dict[str, Any]:
    h_b64, _, _ = split_jwt(token)
    return json.loads(b64url_decode(h_b64))


def decode_payload(token: str) -> dict[str, Any]:
    _, p_b64, _ = split_jwt(token)
    return json.loads(b64url_decode(p_b64))


def encode_segment(obj: dict[str, Any]) -> str:
    """JSON-serialize an object then b64url-encode the result."""
    # `separators=(',', ':')` matches the compact form most libraries emit; that
    # keeps the forged token byte-aligned with the original when the operator
    # is comparing canonical forms side by side.
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


# ── HMAC signing (HS256/HS384/HS512) ──────────────────────────────────────
_HMAC_HASH = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def sign_hmac(alg: str, signing_input: bytes, secret: bytes) -> bytes:
    """Compute the HMAC signature for an HS* algorithm. Raises ValueError."""
    h = _HMAC_HASH.get(alg.upper())
    if h is None:
        raise ValueError(f"unsupported HMAC alg: {alg}")
    return hmac.new(secret, signing_input, h).digest()


def verify_hmac(alg: str, token: str, secret: bytes) -> bool:
    """Constant-time verify of an HS* token against a candidate secret."""
    h, p, sig_b64 = split_jwt(token)
    signing_input = f"{h}.{p}".encode()
    expected = sign_hmac(alg, signing_input, secret)
    try:
        actual = b64url_decode(sig_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, actual)


# ── RSA signing (RS256/384/512) for embedded-jwk self-sign ────────────────
def sign_rsa(alg: str, signing_input: bytes, private_pem: bytes) -> bytes:
    """Sign with an RSA private key. Imports cryptography lazily so the rest of
    the module stays usable if cryptography is somehow unavailable (it isn't,
    in practice — it's already a transitive dep)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    alg = alg.upper()
    hash_alg = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }.get(alg)
    if hash_alg is None:
        raise ValueError(f"unsupported RSA alg: {alg}")

    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.sign(signing_input, padding.PKCS1v15(), hash_alg)


def generate_rsa_keypair_for_embed(bits: int = 2048) -> tuple[bytes, dict]:
    """Generate an RSA keypair and return (private_pem, jwk_public). Used by
    the embedded-jwk self-sign forge — the JWK goes into the header, the
    private key signs the token."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_numbers = priv.public_key().public_numbers()
    # JWK n / e are big-endian base64url, unpadded, minimal byte length.
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    jwk_public = {
        "kty": "RSA",
        "n": b64url_encode(n_bytes),
        "e": b64url_encode(e_bytes),
        "alg": "RS256",
        "use": "sig",
    }
    return private_pem, jwk_public
