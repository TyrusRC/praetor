"""Async client for the burp-expedition control API (TCP/UDP proxy on :18112).

Separate from praetor.client (which targets the praetor-burp-ext REST on :8111);
burp-expedition is a distinct Burp extension exposing its own loopback API. Same
host as Burp (BURP_API_HOST, so WSL works), port EXPEDITION_API_PORT (default
18112). Every call returns a dict; a connection failure returns {"error": ...}
rather than raising, so a tool degrades to a clear message when the extension
isn't loaded.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from praetor.config import BURP_API_HOST

_PORT = int(os.environ.get("EXPEDITION_API_PORT", "18112"))
_BASE = f"http://{BURP_API_HOST}:{_PORT}"
_TIMEOUT = float(os.environ.get("EXPEDITION_API_TIMEOUT", "15"))


def _resolve_token() -> str:
    """Mirror ApiToken.resolve() in the Kotlin extension (ApiSecurity.kt):
    EXPEDITION_API_TOKEN wins when set; otherwise the extension writes a
    random 64-char hex token to <dir>/api-token on first start and reuses it
    on every later start, where <dir> is $EXPEDITION_CA_DIR or ~/.expedition.
    Auth is now MANDATORY on every request (no loopback bypass) — without
    this read every tcp_*/probe_*_unauth call gets a 401.
    """
    env_token = os.environ.get("EXPEDITION_API_TOKEN", "").strip()
    if env_token:
        return env_token
    base = os.environ.get("EXPEDITION_CA_DIR", "").strip() or str(Path.home() / ".expedition")
    try:
        return (Path(base) / "api-token").read_text(encoding="utf-8").strip()
    except OSError:
        return ""  # extension not started yet / file not written — 401 surfaces the real cause


def _headers() -> dict:
    # Resolved per call, not cached at import time: the MCP server is a
    # long-running process that can start before Burp/expedition ever has —
    # ~/.expedition/api-token won't exist yet, and caching an empty token
    # would 401 every call for the rest of the process's life even after the
    # extension starts and writes it. The file read is cheap; correctness
    # here matters more than saving one stat() per call.
    token = _resolve_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


_UNREACHABLE = {
    "error": (
        f"Cannot reach burp-expedition control API at {_BASE}. The control API is "
        "OPT-IN: start Burp with EXPEDITION_API_ENABLE=1 in its environment, then "
        "load the burp-expedition extension (API comes up on :18112). "
        "EXPEDITION_API_DISABLE=1 force-disables it; EXPEDITION_API_PORT overrides "
        "the port. Verify: curl -s " + _BASE + "/status"
    )
}


async def _request(method: str, path: str, json: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(base_url=_BASE, timeout=_TIMEOUT, headers=_headers()) as c:
            r = await c.request(method, path, json=json)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, dict) else {"result": data}
    except httpx.ConnectError:
        return dict(_UNREACHABLE)
    except httpx.HTTPStatusError as e:
        try:
            return e.response.json()
        except ValueError:
            return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except (httpx.HTTPError, ValueError) as e:
        return {"error": f"expedition API error: {e}"}


async def get(path: str) -> dict:
    return await _request("GET", path)


async def get_list(path: str) -> list | dict:
    """GET an endpoint that returns a JSON array (connections/messages/rules)."""
    try:
        async with httpx.AsyncClient(base_url=_BASE, timeout=_TIMEOUT, headers=_headers()) as c:
            r = await c.get(path)
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        return dict(_UNREACHABLE)
    except (httpx.HTTPError, ValueError) as e:
        return {"error": f"expedition API error: {e}"}


async def post(path: str, json: dict | None = None) -> dict:
    return await _request("POST", path, json=json)


async def delete(path: str) -> dict:
    return await _request("DELETE", path)
