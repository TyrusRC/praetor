"""Advanced auth-attack tools: JWT forge / crack, session lifecycle, login
bypass orchestrator, MFA bypass, reset-token entropy analysis.

All HTTP-bearing tools route through Burp via the standard client.post path,
producing logger_index for evidence. Pure-compute tools (forge_jwt,
crack_jwt_secret, analyze_reset_tokens) operate locally — no external deps
beyond stdlib + the already-installed `cryptography` package."""

from mcp.server.fastmcp import FastMCP

from . import (
    forge_jwt as _forge_jwt,
    crack_jwt as _crack_jwt,
    session_lifecycle as _session_lifecycle,
    login_bypass as _login_bypass,
    mfa_bypass as _mfa_bypass,
    reset_tokens as _reset_tokens,
)


def register(mcp: FastMCP):
    _forge_jwt.register(mcp)
    _crack_jwt.register(mcp)
    _session_lifecycle.register(mcp)
    _login_bypass.register(mcp)
    _mfa_bypass.register(mcp)
    _reset_tokens.register(mcp)
