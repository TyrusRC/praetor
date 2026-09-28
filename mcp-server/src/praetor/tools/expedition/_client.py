"""Async client for the burp-expedition control API (TCP/UDP proxy on :8112).

Separate from praetor.client (which targets the praetor-burp-ext REST on :8111);
burp-expedition is a distinct Burp extension exposing its own loopback API. Same
host as Burp (BURP_API_HOST, so WSL works), port EXPEDITION_API_PORT (default
8112). Every call returns a dict; a connection failure returns {"error": ...}
rather than raising, so a tool degrades to a clear message when the extension
isn't loaded.
"""

from __future__ import annotations

import os

import httpx

from praetor.config import BURP_API_HOST

_PORT = int(os.environ.get("EXPEDITION_API_PORT", "8112"))
_BASE = f"http://{BURP_API_HOST}:{_PORT}"
_TIMEOUT = float(os.environ.get("EXPEDITION_API_TIMEOUT", "15"))

_UNREACHABLE = {
    "error": (
        f"Cannot reach burp-expedition control API at {_BASE}. Load the "
        "burp-expedition extension in Burp (it starts the API on :8112), or set "
        "EXPEDITION_API_PORT. Verify: curl -s " + _BASE + "/status"
    )
}


async def _request(method: str, path: str, json: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(base_url=_BASE, timeout=_TIMEOUT) as c:
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
        async with httpx.AsyncClient(base_url=_BASE, timeout=_TIMEOUT) as c:
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
