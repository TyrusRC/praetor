"""Shared OAuth/OIDC flow helpers — extracted from oauth_flow.py (split 2026-07-23).

state/PKCE generation, query/fragment extraction, unverified JWT decode, entropy,
at_hash validation, and the /authorize + /token request builders. Consumed by
oauth_flow / oauth_device_flow / oauth_hybrid_flow / oauth_dpop_audit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import urllib.parse
from typing import Any


from burpsuite_mcp import client


def _gen_state() -> str:
    """Cryptographically-random URL-safe state token."""
    return secrets.token_urlsafe(24)


def _gen_pkce_pair(method: str = "S256") -> tuple[str, str]:
    """Return (code_verifier, code_challenge)."""
    verifier = secrets.token_urlsafe(48)
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    elif method == "plain":
        challenge = verifier
    else:
        raise ValueError(f"unsupported PKCE method: {method}")
    return verifier, challenge


def _extract_query(location: str, key: str) -> str:
    """Pull a query parameter value out of a Location URL. Returns '' on miss."""
    parsed = urllib.parse.urlparse(location)
    qs = urllib.parse.parse_qs(parsed.query)
    return qs.get(key, [""])[0]


def _extract_fragment(location: str, key: str) -> str:
    """Pull a fragment parameter out of a URL (hybrid flow puts tokens in #fragment)."""
    parsed = urllib.parse.urlparse(location)
    frag = parsed.fragment or ""
    fq = urllib.parse.parse_qs(frag)
    return fq.get(key, [""])[0]


def _jwt_decode_unverified(token: str) -> tuple[dict, dict, str]:
    """Best-effort JWT decode WITHOUT signature verification. Returns
    (header, claims, signature_b64). Raises on malformed input."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a 3-part JWT")
    def _b64decode(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)
    header = json.loads(_b64decode(parts[0]))
    claims = json.loads(_b64decode(parts[1]))
    return header, claims, parts[2]


def _shannon_bits_per_char(s: str) -> float:
    """Rough entropy estimate (bits/char). Low for 'AAAAAA', high for random."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _at_hash_match(access_token: str, at_hash: str) -> bool:
    """Validate id_token at_hash claim — SHA-256 leftmost half, base64url, no pad."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    left = digest[: len(digest) // 2]
    computed = base64.urlsafe_b64encode(left).rstrip(b"=").decode("ascii")
    return computed == at_hash


async def _authorize_request(
    authorize_url: str,
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str | None,
    code_challenge_method: str | None,
    extra_query: dict[str, str] | None = None,
    cookies: dict | None = None,
    bearer: str = "",
) -> dict:
    """Build the /authorize URL and fetch with follow_redirects=False."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if code_challenge and code_challenge_method:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method
    if extra_query:
        params.update(extra_query)

    parsed = urllib.parse.urlparse(authorize_url)
    qs = urllib.parse.parse_qs(parsed.query)
    for k, v in params.items():
        qs[k] = [v]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    full_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    payload: dict[str, Any] = {
        "method": "GET",
        "url": full_url,
        "follow_redirects": False,
    }
    if cookies:
        payload["cookies"] = cookies
    if bearer:
        payload["headers"] = {"Authorization": f"Bearer {bearer}"}
    return await client.post("/api/http/curl", json=payload)


async def _token_request(
    token_url: str,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    code_verifier: str | None,
) -> dict:
    """POST /token with grant_type=authorization_code."""
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if client_secret:
        body["client_secret"] = client_secret
    if code_verifier:
        body["code_verifier"] = code_verifier
    body_enc = urllib.parse.urlencode(body)
    return await client.post("/api/http/curl", json={
        "method": "POST",
        "url": token_url,
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": body_enc,
        "follow_redirects": False,
    })
