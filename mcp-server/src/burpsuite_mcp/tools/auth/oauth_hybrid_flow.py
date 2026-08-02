"""oauth_hybrid_flow_simulator — OIDC hybrid flow (code + id_token in fragment). Split from oauth_flow.py (2026-07-23)."""

from __future__ import annotations

import secrets
import urllib.parse
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict
from burpsuite_mcp.tools.auth._oauth_common import (
    _gen_state, _extract_query, _extract_fragment,
    _jwt_decode_unverified, _at_hash_match,
)


def register(mcp: FastMCP) -> None:

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

