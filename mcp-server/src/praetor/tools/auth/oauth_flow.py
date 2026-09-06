"""oauth_flow_simulator — Authorization Code / PKCE flow through Burp (W20-T1). Split from oauth_flow.py (2026-07-23)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._oauth_flow_impl import _run_oauth_flow_simulator
from praetor.tools.auth._oauth_common import (
    _gen_state, _gen_pkce_pair, _extract_query, _authorize_request, _token_request,
)

# Split 2026-07-23: `client` and the helpers below are not referenced in this
# module — they are re-exported so `oauth_flow.<name>` keeps resolving for the
# sibling simulators' tests, which patch and import through this module.
from praetor import client  # noqa: F401
from praetor.tools.auth._oauth_common import (  # noqa: F401
    _at_hash_match, _extract_fragment, _jwt_decode_unverified,
    _shannon_bits_per_char,
)


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
        return await _run_oauth_flow_simulator(
            authorize_url,
            token_url,
            client_id,
            redirect_uri,
            scope=scope,
            client_secret=client_secret,
            code_challenge_method=code_challenge_method,
            skip_pkce=skip_pkce,
            cookies=cookies,
            bearer_token=bearer_token,
        )


    # OAuth aggregator (post-split 2026-07-23): a single oauth_flow.register(mcp)
    # wires all four OAuth flow tools. The sibling modules were extracted to keep
    # each file focused; auth/__init__ calls only this register, and the siblings
    # do NOT self-register there (avoids double registration).
    from praetor.tools.auth import (
        oauth_device_flow, oauth_hybrid_flow, oauth_dpop_audit)
    oauth_device_flow.register(mcp)
    oauth_hybrid_flow.register(mcp)
    oauth_dpop_audit.register(mcp)
