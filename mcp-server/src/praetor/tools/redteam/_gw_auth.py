"""Forward both lanes into Ghostwriter (central reporting/oplog hub):

- network operator-log actions -> `oplogEntry` (the activity timeline)
- web/Burp + network findings   -> `reportedFinding` (attached to a report, so
  they render in the deliverable and Ghostwriter's Findings tab) AND mirrored to
  `oplogEntry` tagged vuln:/severity: so findings are visible on the timeline too

Local .burp-intel stores stay authoritative; unset GHOSTWRITER_URL = no-op. A
per-domain marker prevents duplicate pushes.

NOTE: Hasura column names can drift between Ghostwriter versions — the mappings
here are validated against the installed instance. Re-check on upgrade.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from praetor import config
from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path

from ._oplog import read_oplog



_LOGIN_JWT = ""
_LAST_LOGIN_ERR = ""      # reason the most recent login attempt failed, if any

# GraphQL / Hasura auth-failure hints -> re-login and retry once (JWTs expire).
_AUTH_ERR_HINTS = ("jwt", "authoriz", "authentic", "unauthenticated",
                   "malformed", "signature", "expired")


def _has_static_auth() -> bool:
    return bool(config.GHOSTWRITER_ADMIN_SECRET or config.GHOSTWRITER_API_TOKEN)


def _has_auth() -> bool:
    """Any usable auth path: admin secret, static token, or login credentials."""
    return bool(_has_static_auth() or
                (config.GHOSTWRITER_USERNAME and config.GHOSTWRITER_PASSWORD))


def is_configured() -> bool:
    return bool(config.GHOSTWRITER_URL and _has_auth() and config.GHOSTWRITER_OPLOG_ID)


def config_hint() -> str:
    missing = []
    if not config.GHOSTWRITER_URL:
        missing.append("GHOSTWRITER_URL")
    if not _has_auth():
        missing.append("GHOSTWRITER_API_TOKEN / GHOSTWRITER_ADMIN_SECRET / "
                       "GHOSTWRITER_USERNAME+PASSWORD")
    if not config.GHOSTWRITER_OPLOG_ID:
        missing.append("GHOSTWRITER_OPLOG_ID")
    return "set " + ", ".join(missing) if missing else "configured"


def auth_mode() -> str:
    """Which auth path is active (no secret values). For status output."""
    if config.GHOSTWRITER_ADMIN_SECRET:
        return "admin-secret"
    if config.GHOSTWRITER_API_TOKEN:
        return "api-token"
    if config.GHOSTWRITER_USERNAME and config.GHOSTWRITER_PASSWORD:
        return f"login (user {config.GHOSTWRITER_USERNAME!r})"
    return "none"


def _headers(bearer: str = "") -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if config.GHOSTWRITER_ADMIN_SECRET:
        h["X-Hasura-Admin-Secret"] = config.GHOSTWRITER_ADMIN_SECRET
    elif config.GHOSTWRITER_API_TOKEN:
        h["Authorization"] = f"Bearer {config.GHOSTWRITER_API_TOKEN}"
    elif bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return h


async def _login() -> dict:
    """Mint a JWT from GHOSTWRITER_USERNAME/PASSWORD via Ghostwriter's `login`
    GraphQL action. Returns {'token': ...} or {'error': ...}."""
    if not (config.GHOSTWRITER_USERNAME and config.GHOSTWRITER_PASSWORD):
        return {"error": "no GHOSTWRITER_USERNAME/PASSWORD to log in with"}
    query = ("mutation PraetorLogin($u: String!, $p: String!) "
             "{ login(username: $u, password: $p) { token expires } }")
    variables = {"u": config.GHOSTWRITER_USERNAME, "p": config.GHOSTWRITER_PASSWORD}
    verify = not config.GHOSTWRITER_INSECURE_TLS
    try:
        async with httpx.AsyncClient(timeout=20, verify=verify) as c:
            r = await c.post(f"{config.GHOSTWRITER_URL}/v1/graphql",
                             headers={"Content-Type": "application/json"},
                             json={"query": query, "variables": variables})
    except httpx.HTTPError as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"error": f"login HTTP {r.status_code}: {r.text[:200]}"}
    body = r.json()
    if body.get("errors"):
        return {"error": "; ".join(e.get("message", "?") for e in body["errors"])}
    token = ((body.get("data") or {}).get("login") or {}).get("token", "")
    return {"token": token} if token else {"error": "login returned no token"}


async def _ensure_login_token() -> str:
    """The JWT to bear when no static auth is set. Cached; empty on failure."""
    global _LOGIN_JWT, _LAST_LOGIN_ERR
    if _has_static_auth():
        return ""
    if _LOGIN_JWT:
        return _LOGIN_JWT
    res = await _login()
    _LOGIN_JWT = res.get("token", "")
    _LAST_LOGIN_ERR = res.get("error", "")
    return _LOGIN_JWT


def _is_auth_error(msg: str) -> bool:
    m = msg.lower()
    return any(h in m for h in _AUTH_ERR_HINTS)


async def _gql(query: str, variables: dict) -> dict:
    """POST a GraphQL op. Returns {'data':...} or {'error':...}.

    When auth is username/password login, an expired/invalid JWT is re-minted
    and the request retried once."""
    global _LOGIN_JWT, _LAST_LOGIN_ERR
    url = f"{config.GHOSTWRITER_URL}/v1/graphql"
    # Self-hosted Ghostwriter uses a self-signed cert on https://localhost.
    verify = not config.GHOSTWRITER_INSECURE_TLS
    for attempt in (1, 2):
        bearer = await _ensure_login_token()
        if not _has_static_auth() and not bearer:
            return {"error": f"Ghostwriter login failed: {_LAST_LOGIN_ERR or 'no token'}"}
        try:
            async with httpx.AsyncClient(timeout=20, verify=verify) as c:
                r = await c.post(url, headers=_headers(bearer),
                                 json={"query": query, "variables": variables})
        except httpx.HTTPError as e:
            return {"error": f"{type(e).__name__}: {e}"}
        retriable = attempt == 1 and not _has_static_auth()
        if r.status_code in (401, 403) and retriable:
            _LOGIN_JWT = ""            # stale JWT -> re-login and retry once
            continue
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:300]}"}
        body = r.json()
        if body.get("errors"):
            msg = "; ".join(e.get("message", "?") for e in body["errors"])
            if retriable and _is_auth_error(msg):
                _LOGIN_JWT = ""
                continue
            return {"error": msg}
        return {"data": body.get("data", {})}
    return {"error": "Ghostwriter auth retry exhausted"}



__all__ = ['_LOGIN_JWT', '_AUTH_ERR_HINTS', '_has_static_auth', '_has_auth', 'is_configured', 'config_hint', 'auth_mode', '_headers', '_login', '_ensure_login_token', '_is_auth_error', '_gql']
