"""Step-up markers + request/classify helpers for passkey_stepup."""

from __future__ import annotations

import json

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers

# WebAuthn assertion. Matched against response body + Set-Cookie header.
_VERIFIED_MARKERS = (
    '"verified":true',
    '"verified": true',
    '"step_up":"passed"',
    '"step_up": "passed"',
    '"secure_verification":true',
    '"secure_verification": true',
    "verified=1",
    "secure_verification_token=",
    "stepup_verified=true",
)

# Server markers indicating the server CORRECTLY required a WebAuthn assertion.
# Presence of these → FAILED (server is patched / configured correctly).
_ASSERTION_REQUIRED_MARKERS = (
    "invalid_credential",
    "credential_not_found",
    "assertion_required",
    "missing_assertion",
    "challenge_required",
    "webauthn_assertion",
    "publicKeyCredential",
)


def _build_headers(
    base_url: str,
    cookies: dict | None,
    bearer: str,
    extra: dict | None = None,
) -> dict:
    """Merge realistic Chrome 131 profile + caller auth."""
    headers = apply_realistic_headers(base_url, {})
    headers["Content-Type"] = "application/json"
    if cookies:
        # %3B escape so operator-supplied cookie values stay safe
        cookie_str = "; ".join(f"{k}={str(v).replace(';', '%3B')}"
                               for k, v in cookies.items())
        headers["Cookie"] = cookie_str
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if extra:
        headers.update(extra)
    return headers


async def _send_stepup(url: str, headers: dict, body: dict) -> dict:
    """POST a JSON body to the step-up endpoint via curl_request (Burp-routed)."""
    return await client.post("/api/http/curl", json={
        "method": "POST",
        "url": url,
        "headers": headers,
        "data": json.dumps(body),
        "follow_redirects": False,
    })


async def _send_protected(url: str, headers: dict, method: str = "GET") -> dict:
    """GET the protected resource to verify the bypass actually opened the gate."""
    return await client.post("/api/http/curl", json={
        "method": method,
        "url": url,
        "headers": headers,
        "follow_redirects": False,
    })


def _classify_response(resp: dict) -> tuple[bool, bool, str]:
    """Return (looks_verified, requires_assertion, hit_marker).

    looks_verified — server returned a marker indicating bogus-bypass success
    requires_assertion — server returned a marker requiring real WebAuthn
    hit_marker — the specific string that fired (for evidence)
    """
    body = resp.get("response_body") or ""
    headers = resp.get("response_headers") or []
    haystack = body + "\n"
    for h in headers:
        if isinstance(h, dict):
            haystack += f"{h.get('name', '')}: {h.get('value', '')}\n"
        elif isinstance(h, str):
            haystack += h + "\n"

    haystack_lower = haystack.lower()
    for marker in _VERIFIED_MARKERS:
        if marker.lower() in haystack_lower:
            return True, False, marker
    for marker in _ASSERTION_REQUIRED_MARKERS:
        if marker.lower() in haystack_lower:
            return False, True, marker
    return False, False, ""
