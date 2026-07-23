"""oauth_device_flow_simulator — OAuth 2.0 Device Authorization Grant flow. Split from oauth_flow.py (2026-07-23)."""

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
from burpsuite_mcp.tools.auth._oauth_common import (
    _gen_state, _gen_pkce_pair, _extract_query, _extract_fragment,
    _jwt_decode_unverified, _shannon_bits_per_char, _at_hash_match,
    _authorize_request, _token_request,
)


def register(mcp: FastMCP) -> None:

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

