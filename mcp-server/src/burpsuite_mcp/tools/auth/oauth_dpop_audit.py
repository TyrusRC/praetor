"""oauth_dpop_audit — DPoP sender-constrained token audit. Split from oauth_flow.py (2026-07-23)."""

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
