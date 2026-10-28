"""Standardised error envelope for MCP tool returns."""


def err(msg: str, **kw: object) -> dict:
    """Return a dict with an ``error`` key so callers can test ``if "error" in result``."""
    return {"error": msg, **kw}
