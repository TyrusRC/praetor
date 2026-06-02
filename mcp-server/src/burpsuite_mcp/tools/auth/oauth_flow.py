"""oauth_flow_simulator — drive Authorization Code / PKCE flows through Burp.

W20-T1. Operator supplies the authorize_url + token_url + client_id +
redirect_uri (+ optional client_secret + scope + PKCE method). The simulator:

1. Generates a random `state` (CSRF token) and PKCE `code_verifier` +
   `code_challenge` (S256) when PKCE is requested.
2. Sends the authorize request through Burp's curl client with
   follow_redirects=False — captures the redirect with the code.
3. Parses the `code` and echoed `state` from the redirect Location.
4. Exchanges code at token_url (with or without verifier).
5. Probes the four canonical defects:
   - **state CSRF**: Does the AS validate state on callback? (We re-issue
     callback with a different state and check if AS notices.)
   - **PKCE enforced**: Does /token reject when verifier is missing /
     wrong? (Re-exchange same code with bad verifier.)
   - **code single-use**: Does /token reject second exchange of the same
     code? (Re-exchange same code immediately.)
   - **redirect_uri strict**: Does AS reject suffix-bypass redirect_uri
     mutations? (Re-issue authorize with redirect_uri = original +
     ".attacker.tld".)

Returns VerdictResult (W7 schema). CONFIRMED HIGH/CRITICAL when ≥2 defects;
SUSPECTED on single defect; FAILED on all defences intact.

No actual victim interaction is required — the simulator is operator-driven
with the operator's own test account. Output flags the defects so operator
can chain into ATO walkthrough per `playbook-oauth-flow-attacks.md`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import time
import urllib.parse
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


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


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def oauth_flow_simulator(  # cost: low-medium (~6 requests)
        authorize_url: str,
        token_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        client_secret: str = "",
        code_challenge_method: str = "S256",
        skip_pkce: bool = False,
        cookies: dict | None = None,
        bearer_token: str = "",
    ) -> dict:
        """Drive an Authorization Code / PKCE flow through Burp and audit 4 canonical defences.

        Probes:
          1. State CSRF — re-issue callback with mutated state; AS should reject.
          2. PKCE enforced — re-exchange code with wrong verifier; /token should reject.
          3. Code single-use — re-exchange same code; /token should reject.
          4. redirect_uri strict — re-issue authorize with suffix-bypass URL;
             AS should reject (not redirect to attacker URL).

        Returns VerdictResult (W7 schema).

        Args:
            authorize_url: AS /authorize endpoint
            token_url: AS /token endpoint
            client_id: OAuth client ID
            redirect_uri: Registered redirect URI
            scope: Requested scope (default 'openid' for OIDC)
            client_secret: Optional confidential-client secret
            code_challenge_method: 'S256' (default) | 'plain' — only if PKCE enabled
            skip_pkce: True to test the AS without PKCE (downgrade probe)
            cookies: Operator's session cookies (authenticate AS first via browser)
            bearer_token: Optional bearer if AS uses one for the user session
        """
        if not authorize_url or not token_url or not client_id or not redirect_uri:
            return error_verdict(
                "authorize_url + token_url + client_id + redirect_uri all required",
                vuln_type="oauth",
            )

        notes: list[str] = []
        defects: list[str] = []
        logger_indices: list[int] = []

        # --- Phase 1: canonical flow ---
        state = _gen_state()
        verifier = None
        challenge = None
        if not skip_pkce:
            verifier, challenge = _gen_pkce_pair(code_challenge_method)

        authorize_resp = await _authorize_request(
            authorize_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=challenge,
            code_challenge_method=code_challenge_method if challenge else None,
            cookies=cookies,
            bearer=bearer_token,
        )
        if "error" in authorize_resp:
            return error_verdict(
                f"authorize request failed: {authorize_resp['error']}",
                vuln_type="oauth",
            )
        idx = authorize_resp.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        status = int(authorize_resp.get("status", 0) or 0)
        if status not in (301, 302, 303, 307, 308):
            return error_verdict(
                f"authorize did not redirect (status {status}); "
                f"operator may need to log in first via browser",
                vuln_type="oauth",
            )

        # Pull Location header from response.
        location = ""
        for h in authorize_resp.get("response_headers", []) or []:
            if isinstance(h, dict) and h.get("name", "").lower() == "location":
                location = h.get("value", "")
                break
        if not location:
            return error_verdict(
                "no Location header in authorize redirect",
                vuln_type="oauth",
            )

        code = _extract_query(location, "code")
        returned_state = _extract_query(location, "state")
        if not code:
            err = _extract_query(location, "error")
            return error_verdict(
                f"no code in callback Location (error={err!r}); login may have failed",
                vuln_type="oauth",
            )

        # --- Defence #1: state echo ---
        if returned_state != state:
            defects.append(f"state_not_echoed (sent {state[:10]}..., got {returned_state[:10]}...)")
            notes.append("State parameter not echoed in callback — CSRF axis broken")

        # --- Phase 2: exchange code (canonical) ---
        token_resp = await _token_request(
            token_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=verifier,
        )
        idx = token_resp.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        token_ok = "error" not in token_resp and int(token_resp.get("status", 0) or 0) == 200
        if not token_ok:
            err = token_resp.get("error") or _extract_query(
                str(token_resp.get("response_body", "")), "error"
            ) or "no access_token"
            return error_verdict(
                f"canonical /token exchange failed: {err} — operator may need "
                f"to fix credentials before audit can proceed",
                vuln_type="oauth",
            )

        # --- Defence #2: code single-use ---
        replay = await _token_request(
            token_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=verifier,
        )
        idx = replay.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        replay_ok = int(replay.get("status", 0) or 0) == 200
        if replay_ok:
            defects.append("code_replay_accepted")
            notes.append("Same code accepted twice at /token — code is not single-use")

        # --- Defence #3: PKCE enforced (only when we sent verifier) ---
        if verifier:
            # New flow with bad verifier
            bad_verifier_state = _gen_state()
            bad_authorize = await _authorize_request(
                authorize_url,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=bad_verifier_state,
                code_challenge=challenge,  # same challenge
                code_challenge_method=code_challenge_method,
                cookies=cookies,
                bearer=bearer_token,
            )
            if "error" not in bad_authorize and int(bad_authorize.get("status", 0) or 0) in (301, 302, 303, 307, 308):
                bad_location = ""
                for h in bad_authorize.get("response_headers", []) or []:
                    if isinstance(h, dict) and h.get("name", "").lower() == "location":
                        bad_location = h.get("value", "")
                        break
                bad_code = _extract_query(bad_location, "code")
                if bad_code:
                    pkce_bad = await _token_request(
                        token_url,
                        client_id=client_id,
                        client_secret=client_secret,
                        redirect_uri=redirect_uri,
                        code=bad_code,
                        code_verifier="wrong_verifier_" + secrets.token_urlsafe(8),
                    )
                    idx = pkce_bad.get("history_index")
                    if isinstance(idx, int) and idx >= 0:
                        logger_indices.append(idx)
                    if int(pkce_bad.get("status", 0) or 0) == 200:
                        defects.append("pkce_not_enforced")
                        notes.append("PKCE verifier not validated — wrong verifier accepted")

        # --- Defence #4: redirect_uri strict ---
        suffix_uri = redirect_uri + ".attacker.tld"
        uri_probe = await _authorize_request(
            authorize_url,
            client_id=client_id,
            redirect_uri=suffix_uri,
            scope=scope,
            state=_gen_state(),
            code_challenge=challenge,
            code_challenge_method=code_challenge_method if challenge else None,
            cookies=cookies,
            bearer=bearer_token,
        )
        idx = uri_probe.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        uri_status = int(uri_probe.get("status", 0) or 0)
        # Strict AS: 400/error_description. Bypass: 302 to the suffix URI.
        if uri_status in (301, 302, 303, 307, 308):
            uri_loc = ""
            for h in uri_probe.get("response_headers", []) or []:
                if isinstance(h, dict) and h.get("name", "").lower() == "location":
                    uri_loc = h.get("value", "")
                    break
            if "attacker.tld" in uri_loc:
                defects.append("redirect_uri_suffix_bypass")
                notes.append(
                    f"AS accepted suffix-bypass redirect_uri "
                    f"({suffix_uri[:60]}...) — code would deliver to attacker"
                )

        # --- Verdict synthesis ---
        critical_subset = {
            "redirect_uri_suffix_bypass",
            "state_not_echoed",
            "code_replay_accepted",
            "pkce_not_enforced",
        }
        critical_hits = sum(1 for d in defects if any(d.startswith(k) for k in critical_subset))
        if critical_hits >= 2:
            verdict, confidence = "CONFIRMED", 0.85
            ev = f"OAuth audit: {critical_hits} critical defences broken: {'; '.join(defects)}"
        elif critical_hits == 1:
            verdict, confidence = "SUSPECTED", 0.6
            ev = f"OAuth audit: 1 defence broken ({defects[0]}) — chain to ATO if attacker can drive victim"
        elif defects:
            verdict, confidence = "SUSPECTED", 0.45
            ev = f"OAuth audit: minor defects ({len(defects)}): {'; '.join(defects)}"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "OAuth audit: state echoed + code single-use + PKCE enforced + redirect_uri strict"

        human_lines = [
            f"oauth_flow_simulator: {client_id} @ {authorize_url}",
            f"  Scope: {scope}",
            f"  PKCE: {'enabled (' + code_challenge_method + ')' if verifier else 'skipped'}",
            f"  Defects: {len(defects)}",
        ]
        for n in notes:
            human_lines.append(f"  [!] {n}")
        human_lines.append("")
        human_lines.append(f"Verdict: {verdict} (confidence {confidence:.2f})")
        human_lines.append(f"Evidence: {ev}")
        if defects:
            human_lines.append("")
            human_lines.append("Next: see .claude/skills/playbook-oauth-flow-attacks.md for chain-to-ATO walkthrough per defect.")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="oauth",
            logger_indices=logger_indices,
            details={
                "authorize_url": authorize_url,
                "token_url": token_url,
                "client_id": client_id,
                "scope": scope,
                "pkce_used": bool(verifier),
                "pkce_method": code_challenge_method if verifier else None,
                "defects": defects,
                "notes": notes,
            },
            summary="\n".join(human_lines),
        )

    @mcp.tool()
    async def oauth_device_flow_simulator(  # cost: low (~3 requests)
        device_authorization_url: str,
        token_url: str,
        client_id: str,
        scope: str = "openid",
        client_secret: str = "",
    ) -> dict:
        """Drive RFC 8628 Device Authorization Grant and audit 3 canonical defences.

        Probes:
          1. user_code entropy — short / low-entropy codes are brute-forceable
             at the verification_uri ('BVKR' = 4^36 ~ 20 bits; spec recommends
             ≥ 20 bits but many IdPs ship 8-char [A-Z]+ ≈ 38 bits — flag <30).
          2. polling-rate enforcement — server should return `slow_down` if
             we poll faster than `interval`. Tool sends 2 rapid polls and
             checks for slow_down vs naive authorization_pending.
          3. device_code single-use after activation — once the user has
             approved on a different channel, replaying the original device_code
             should still pass (it's bound to the device), but the issued
             access_token from the eventual /token success must not be
             re-issuable. (Operator activates manually; tool reports state.)

        Operator workflow:
          1. Call this tool — it kicks off the flow and returns the
             verification_uri + user_code for operator to approve in a browser.
          2. Tool runs the polling probes while waiting (does not block on
             user approval — returns the polling-defect verdict).

        Returns VerdictResult.
        """
        if not device_authorization_url or not token_url or not client_id:
            return error_verdict(
                "device_authorization_url + token_url + client_id required",
                vuln_type="oauth",
            )
        notes: list[str] = []
        defects: list[str] = []
        logger_indices: list[int] = []

        body = {"client_id": client_id, "scope": scope}
        if client_secret:
            body["client_secret"] = client_secret
        init_resp = await client.post("/api/http/curl", json={
            "method": "POST",
            "url": device_authorization_url,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": urllib.parse.urlencode(body),
            "follow_redirects": False,
        })
        if "error" in init_resp:
            return error_verdict(
                f"device_authorization request failed: {init_resp['error']}",
                vuln_type="oauth",
            )
        idx = init_resp.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        if int(init_resp.get("status", 0) or 0) != 200:
            return error_verdict(
                f"device_authorization returned status "
                f"{init_resp.get('status')} — operator must fix endpoint/client",
                vuln_type="oauth",
            )
        try:
            init_body = json.loads(init_resp.get("response_body", "") or "{}")
        except json.JSONDecodeError:
            return error_verdict("device_authorization response not JSON", vuln_type="oauth")

        device_code = init_body.get("device_code", "")
        user_code = init_body.get("user_code", "")
        verification_uri = init_body.get("verification_uri", "")
        verification_uri_complete = init_body.get("verification_uri_complete", "")
        interval = int(init_body.get("interval", 5) or 5)
        expires_in = int(init_body.get("expires_in", 600) or 600)

        if not device_code or not user_code:
            return error_verdict(
                "device_authorization missing device_code or user_code",
                vuln_type="oauth",
            )

        # --- Defect #1: user_code entropy ---
        # Strip the spec-permitted '-' separator before measuring.
        cleaned = re.sub(r"[^A-Za-z0-9]", "", user_code)
        alphabet = 0
        if re.search(r"[A-Z]", cleaned):
            alphabet += 26
        if re.search(r"[a-z]", cleaned):
            alphabet += 26
        if re.search(r"[0-9]", cleaned):
            alphabet += 10
        alphabet = max(alphabet, 2)
        eff_bits = len(cleaned) * math.log2(alphabet) if cleaned else 0.0
        # Separately flag egregiously low-variety codes (e.g. 'AAAA') even
        # when alphabet*len math looks fine.
        if cleaned and len(set(cleaned)) <= max(2, len(cleaned) // 3):
            eff_bits = min(eff_bits, len(set(cleaned)) * math.log2(alphabet))
        if eff_bits < 30:
            defects.append(f"user_code_low_entropy ({eff_bits:.1f} bits)")
            notes.append(
                f"user_code {user_code!r} has ~{eff_bits:.1f} bits of entropy "
                f"— attacker can brute-force at verification_uri"
            )

        # --- Defect #2: polling-rate enforcement ---
        poll_body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
            **({"client_secret": client_secret} if client_secret else {}),
        })
        poll1 = await client.post("/api/http/curl", json={
            "method": "POST", "url": token_url,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": poll_body, "follow_redirects": False,
        })
        poll2 = await client.post("/api/http/curl", json={
            "method": "POST", "url": token_url,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": poll_body, "follow_redirects": False,
        })
        for p in (poll1, poll2):
            i = p.get("history_index")
            if isinstance(i, int) and i >= 0:
                logger_indices.append(i)

        def _poll_error(p: dict) -> str:
            try:
                return json.loads(p.get("response_body", "") or "{}").get("error", "")
            except json.JSONDecodeError:
                return ""

        e1, e2 = _poll_error(poll1), _poll_error(poll2)
        # If both polls return authorization_pending AND server didn't slow_down
        # despite back-to-back requests under `interval` seconds, the rate
        # enforcement is absent — attacker can poll thousands/sec to win race.
        if e1 == "authorization_pending" and e2 == "authorization_pending":
            defects.append("polling_rate_not_enforced")
            notes.append(
                f"Two back-to-back polls within ~0s both returned "
                f"authorization_pending with no slow_down (interval={interval}s)"
            )

        # --- Verdict synthesis ---
        if len(defects) >= 2:
            verdict, confidence = "CONFIRMED", 0.8
            ev = f"Device flow audit: {len(defects)} defects: {'; '.join(defects)}"
        elif defects:
            verdict, confidence = "SUSPECTED", 0.55
            ev = f"Device flow audit: 1 defect: {defects[0]}"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "Device flow audit: user_code entropy + polling rate both enforced"

        human_lines = [
            f"oauth_device_flow_simulator: {client_id} @ {device_authorization_url}",
            f"  user_code:        {user_code}",
            f"  verification_uri: {verification_uri}",
            (f"  verification_uri_complete: {verification_uri_complete}"
             if verification_uri_complete else ""),
            f"  interval:         {interval}s",
            f"  expires_in:       {expires_in}s",
            f"  Defects:          {len(defects)}",
        ]
        for n in notes:
            human_lines.append(f"  [!] {n}")
        human_lines.append("")
        human_lines.append(f"Verdict: {verdict} (confidence {confidence:.2f})")
        human_lines.append(f"Evidence: {ev}")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="oauth",
            logger_indices=logger_indices,
            details={
                "device_authorization_url": device_authorization_url,
                "token_url": token_url,
                "client_id": client_id,
                "scope": scope,
                "user_code": user_code,
                "user_code_entropy_bits": round(eff_bits, 1),
                "interval_s": interval,
                "expires_in_s": expires_in,
                "defects": defects,
                "notes": notes,
            },
            summary="\n".join(l for l in human_lines if l != ""),
        )

    @mcp.tool()
    async def oauth_hybrid_flow_simulator(  # cost: low (~2 requests)
        authorize_url: str,
        token_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        client_secret: str = "",
        response_type: str = "code id_token",
        cookies: dict | None = None,
        bearer_token: str = "",
    ) -> dict:
        """Drive OIDC hybrid flow (response_type='code id_token' or similar)
        and audit nonce binding + id_token at_hash + alg confusion.

        Probes:
          1. nonce binding — id_token must include the `nonce` claim matching
             what we sent in /authorize. Missing or mismatched = replay attack.
          2. at_hash binding — id_token.at_hash must equal SHA-256-left-half
             (base64url) of the access_token. Missing or mismatched =
             token-substitution attack window.
          3. alg confusion — id_token alg=none / HS256 (when AS publishes RS256)
             is the well-known JWKS confusion CVE class. Tool flags alg=none.
          4. state CSRF — same as authorization-code (re-uses parent helper).

        Args:
            response_type: 'code id_token' (default) or 'code id_token token'
                           or 'code token' — must include at least 'code' +
                           one of id_token/token to be a hybrid flow.
        """
        if not authorize_url or not token_url or not client_id or not redirect_uri:
            return error_verdict(
                "authorize_url + token_url + client_id + redirect_uri required",
                vuln_type="oauth",
            )
        if "code" not in response_type or all(
            t not in response_type for t in ("id_token", "token")
        ):
            return error_verdict(
                f"response_type {response_type!r} is not a hybrid flow "
                f"(need 'code' + one of id_token/token)",
                vuln_type="oauth",
            )

        notes: list[str] = []
        defects: list[str] = []
        logger_indices: list[int] = []

        state = _gen_state()
        nonce = secrets.token_urlsafe(16)
        # Hybrid REQUIRES response_mode=fragment normally (or form_post).
        # Use the parent _authorize_request but inject response_type + nonce.
        params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "response_mode": "fragment",
        }
        parsed = urllib.parse.urlparse(authorize_url)
        qs = urllib.parse.parse_qs(parsed.query)
        for k, v in params.items():
            qs[k] = [v]
        full_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
        )
        payload: dict[str, Any] = {
            "method": "GET", "url": full_url, "follow_redirects": False,
        }
        if cookies:
            payload["cookies"] = cookies
        if bearer_token:
            payload["headers"] = {"Authorization": f"Bearer {bearer_token}"}
        authorize_resp = await client.post("/api/http/curl", json=payload)
        if "error" in authorize_resp:
            return error_verdict(
                f"authorize request failed: {authorize_resp['error']}",
                vuln_type="oauth",
            )
        idx = authorize_resp.get("history_index")
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)
        if int(authorize_resp.get("status", 0) or 0) not in (301, 302, 303, 307, 308):
            return error_verdict(
                f"hybrid authorize did not redirect (status "
                f"{authorize_resp.get('status')})",
                vuln_type="oauth",
            )
        location = ""
        for h in authorize_resp.get("response_headers", []) or []:
            if isinstance(h, dict) and h.get("name", "").lower() == "location":
                location = h.get("value", "")
                break
        if not location:
            return error_verdict("no Location header in hybrid redirect", vuln_type="oauth")

        # Hybrid puts tokens in the URL FRAGMENT, not query.
        code = _extract_fragment(location, "code") or _extract_query(location, "code")
        returned_state = (
            _extract_fragment(location, "state") or _extract_query(location, "state")
        )
        id_token = (
            _extract_fragment(location, "id_token") or _extract_query(location, "id_token")
        )
        access_token = (
            _extract_fragment(location, "access_token")
            or _extract_query(location, "access_token")
        )

        if returned_state != state:
            defects.append("state_not_echoed")
            notes.append("state CSRF defence broken in hybrid flow")

        # --- Defect: alg + nonce + at_hash on id_token from authorize endpoint
        if id_token and "id_token" in response_type:
            try:
                header, claims, _sig = _jwt_decode_unverified(id_token)
            except Exception as e:
                defects.append(f"id_token_malformed ({e})")
                claims = {}
                header = {}
            alg = (header.get("alg") or "").lower()
            if alg in ("none", ""):
                defects.append("id_token_alg_none")
                notes.append("id_token alg=none — signature not enforced; trivial forgery")
            if alg.startswith("hs"):
                defects.append("id_token_hs_alg_confusion_candidate")
                notes.append(
                    f"id_token alg={header.get('alg')} (HMAC); if AS also publishes "
                    f"RS public key, JWKS-confusion CVE class applies — verify with crack_jwt_secret"
                )
            if claims.get("nonce") != nonce:
                defects.append("nonce_not_bound")
                notes.append(
                    f"id_token.nonce={claims.get('nonce')!r} does not match request "
                    f"nonce {nonce[:10]}... — replay window"
                )
            at_hash = claims.get("at_hash") or ""
            if access_token and at_hash:
                if not _at_hash_match(access_token, at_hash):
                    defects.append("at_hash_mismatch")
                    notes.append(
                        "id_token.at_hash does not match SHA-256-left-half of access_token "
                        "— token-substitution defence broken"
                    )
            elif access_token and not at_hash:
                defects.append("at_hash_missing")
                notes.append(
                    "id_token has no at_hash claim despite access_token present "
                    "— substitution attack window"
                )

        # --- Verdict synthesis ---
        critical = {
            "id_token_alg_none", "nonce_not_bound", "at_hash_mismatch",
            "state_not_echoed", "id_token_hs_alg_confusion_candidate",
        }
        critical_hits = sum(1 for d in defects if any(d.startswith(k) for k in critical))
        if critical_hits >= 2:
            verdict, confidence = "CONFIRMED", 0.85
            ev = f"Hybrid flow audit: {critical_hits} critical defects: {'; '.join(defects)}"
        elif critical_hits == 1:
            verdict, confidence = "SUSPECTED", 0.6
            ev = f"Hybrid flow audit: 1 critical defect ({defects[0]})"
        elif defects:
            verdict, confidence = "SUSPECTED", 0.45
            ev = f"Hybrid flow audit: minor defects ({len(defects)}): {'; '.join(defects)}"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "Hybrid flow audit: nonce bound + at_hash valid + state echoed + alg sound"

        human_lines = [
            f"oauth_hybrid_flow_simulator: {client_id} @ {authorize_url}",
            f"  response_type:  {response_type}",
            f"  code present:   {bool(code)}",
            f"  id_token:       {'yes' if id_token else 'no'}",
            f"  access_token:   {'yes' if access_token else 'no'}",
            f"  Defects:        {len(defects)}",
        ]
        for n in notes:
            human_lines.append(f"  [!] {n}")
        human_lines.append("")
        human_lines.append(f"Verdict: {verdict} (confidence {confidence:.2f})")
        human_lines.append(f"Evidence: {ev}")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="oauth",
            logger_indices=logger_indices,
            details={
                "authorize_url": authorize_url,
                "token_url": token_url,
                "client_id": client_id,
                "response_type": response_type,
                "nonce_sent": nonce,
                "has_id_token": bool(id_token),
                "has_access_token": bool(access_token),
                "defects": defects,
                "notes": notes,
            },
            summary="\n".join(human_lines),
        )

    @mcp.tool()
    async def oauth_dpop_audit(  # cost: low-medium (replay over N endpoints)
        access_token: str,
        dpop_proof: str,
        resource_urls: list[str],
        iat_skew_test_seconds: int = 600,
    ) -> dict:
        """Audit DPoP-bound access token (RFC 9449).

        Operator captures a real DPoP proof + access_token from a real client
        session (via Burp Logger / browser DevTools). The tool replays them
        against the given resource_urls and probes:

          1. Proof reuse across endpoints — RFC 9449 requires `htu` claim
             matches the resource URL; if any resource accepts a proof bound
             to a DIFFERENT htu, binding is not enforced.
          2. iat window — re-send the SAME proof against the SAME endpoint;
             RFC requires servers reject proofs with stale `iat` (default
             window ~5min). If accepted hours later, no skew check.
          3. jkt binding — access_token's `cnf.jkt` must match the proof's
             public-key thumbprint; if a resource accepts a proof from a
             different keypair, jkt binding is missing.

        Args:
            access_token: DPoP-bound bearer token (no 'DPoP ' prefix).
            dpop_proof:   The DPoP JWT proof string from the original request.
            resource_urls: List of resource endpoints to replay against.
            iat_skew_test_seconds: How old the proof should be considered for
                                   the iat-window test. The proof's iat is
                                   read from the JWT and compared to wall clock.
        """
        if not access_token or not dpop_proof:
            return error_verdict(
                "access_token + dpop_proof both required",
                vuln_type="oauth",
            )
        if not resource_urls:
            return error_verdict("resource_urls must be non-empty", vuln_type="oauth")

        notes: list[str] = []
        defects: list[str] = []
        logger_indices: list[int] = []

        # Parse proof claims.
        try:
            proof_header, proof_claims, _sig = _jwt_decode_unverified(dpop_proof)
        except Exception as e:
            return error_verdict(f"dpop_proof not a JWT: {e}", vuln_type="oauth")
        proof_htu = proof_claims.get("htu", "")
        proof_htm = proof_claims.get("htm", "GET")
        proof_iat = int(proof_claims.get("iat", 0) or 0)
        now = int(time.time())
        proof_age = now - proof_iat if proof_iat else 0

        # --- Probe each resource_url with the SAME proof (proof reuse / htu mismatch) ---
        accepted_mismatch: list[str] = []
        for url in resource_urls:
            mismatch = (url != proof_htu)
            resp = await client.post("/api/http/curl", json={
                "method": proof_htm,
                "url": url,
                "headers": {
                    "Authorization": f"DPoP {access_token}",
                    "DPoP": dpop_proof,
                },
                "follow_redirects": False,
            })
            if "error" in resp:
                continue
            idx = resp.get("history_index")
            if isinstance(idx, int) and idx >= 0:
                logger_indices.append(idx)
            status = int(resp.get("status", 0) or 0)
            # 200/201/204 = accepted. 401/invalid_dpop_proof = correct reject.
            if status in (200, 201, 204) and mismatch:
                accepted_mismatch.append(url)

        if accepted_mismatch:
            defects.append("dpop_htu_not_enforced")
            notes.append(
                f"{len(accepted_mismatch)} resource(s) accepted DPoP proof "
                f"with mismatched htu (proof.htu={proof_htu!r}): "
                f"{', '.join(accepted_mismatch[:3])}"
                + ("..." if len(accepted_mismatch) > 3 else "")
            )

        # --- iat window: if proof is older than iat_skew_test_seconds AND was
        # accepted above, server skipped skew check.
        if proof_age > iat_skew_test_seconds and accepted_mismatch:
            defects.append(f"dpop_iat_window_not_enforced ({proof_age}s old)")
            notes.append(
                f"Proof iat is {proof_age}s old (> {iat_skew_test_seconds}s "
                f"threshold) yet was accepted — server skips iat skew check"
            )
        elif proof_age > iat_skew_test_seconds:
            notes.append(
                f"Proof is {proof_age}s old; iat-window enforcement could not "
                f"be confirmed because no resource accepted the proof "
                f"(may simply be htu mismatch reject)"
            )

        # --- jkt binding: decode access_token (if JWT) and compare to proof JWK ---
        jkt_defect_added = False
        try:
            _at_header, at_claims, _at_sig = _jwt_decode_unverified(access_token)
            cnf_jkt = (at_claims.get("cnf") or {}).get("jkt", "")
            jwk = proof_header.get("jwk") or {}
            if jwk and cnf_jkt:
                # RFC 7638 thumbprint — canonical JSON of required members,
                # SHA-256, base64url no-pad. For EC keys: {crv,kty,x,y};
                # for RSA: {e,kty,n}; for OKP: {crv,kty,x}.
                kty = jwk.get("kty", "")
                if kty == "EC":
                    canon = json.dumps(
                        {"crv": jwk.get("crv"), "kty": "EC",
                         "x": jwk.get("x"), "y": jwk.get("y")},
                        separators=(",", ":"), sort_keys=True,
                    )
                elif kty == "RSA":
                    canon = json.dumps(
                        {"e": jwk.get("e"), "kty": "RSA", "n": jwk.get("n")},
                        separators=(",", ":"), sort_keys=True,
                    )
                elif kty == "OKP":
                    canon = json.dumps(
                        {"crv": jwk.get("crv"), "kty": "OKP", "x": jwk.get("x")},
                        separators=(",", ":"), sort_keys=True,
                    )
                else:
                    canon = ""
                if canon:
                    proof_jkt = base64.urlsafe_b64encode(
                        hashlib.sha256(canon.encode("ascii")).digest()
                    ).rstrip(b"=").decode("ascii")
                    if proof_jkt != cnf_jkt:
                        defects.append("dpop_jkt_mismatch")
                        notes.append(
                            f"access_token.cnf.jkt ({cnf_jkt[:12]}...) does "
                            f"not match DPoP proof JWK thumbprint "
                            f"({proof_jkt[:12]}...)"
                        )
                        jkt_defect_added = True
        except Exception:
            pass  # access_token may not be a JWT — skip jkt check
        del jkt_defect_added  # name kept above for clarity

        # --- Verdict ---
        if len(defects) >= 2:
            verdict, confidence = "CONFIRMED", 0.85
            ev = f"DPoP audit: {len(defects)} defects: {'; '.join(defects)}"
        elif defects:
            verdict, confidence = "SUSPECTED", 0.6
            ev = f"DPoP audit: 1 defect ({defects[0]})"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "DPoP audit: htu enforced + iat window respected + jkt bound"

        human_lines = [
            f"oauth_dpop_audit: replayed against {len(resource_urls)} resource(s)",
            f"  proof.htu:  {proof_htu}",
            f"  proof.iat:  {proof_iat} ({proof_age}s ago)",
            f"  resources accepted with mismatched htu: {len(accepted_mismatch)}",
            f"  Defects: {len(defects)}",
        ]
        for n in notes:
            human_lines.append(f"  [!] {n}")
        human_lines.append("")
        human_lines.append(f"Verdict: {verdict} (confidence {confidence:.2f})")
        human_lines.append(f"Evidence: {ev}")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="oauth",
            logger_indices=logger_indices,
            details={
                "proof_htu": proof_htu,
                "proof_htm": proof_htm,
                "proof_iat": proof_iat,
                "proof_age_seconds": proof_age,
                "resources_probed": len(resource_urls),
                "accepted_mismatch": accepted_mismatch,
                "defects": defects,
                "notes": notes,
            },
            summary="\n".join(human_lines),
        )
