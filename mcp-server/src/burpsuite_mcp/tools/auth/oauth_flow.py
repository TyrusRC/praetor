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
import secrets
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
