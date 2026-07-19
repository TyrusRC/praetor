import asyncio

import httpx
from burpsuite_mcp.config import BASE_URL, BURP_API_TIMEOUT


# Reuse a single AsyncClient across calls so we get HTTP keep-alive and
# don't pay TCP setup/teardown on every tool invocation. The client is
# created lazily inside the running event loop.
_shared_client: httpx.AsyncClient | None = None
_client_lock: asyncio.Lock | None = None


def _shared_lock() -> asyncio.Lock:
    global _client_lock
    if _client_lock is None:
        _client_lock = asyncio.Lock()
    return _client_lock


async def _get_client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None:
        async with _shared_lock():
            if _shared_client is None:
                _shared_client = httpx.AsyncClient(
                    base_url=BASE_URL,
                    timeout=BURP_API_TIMEOUT,
                    # Align keepalive with the Java extension's fixed 24-thread pool.
                    limits=httpx.Limits(max_connections=32, max_keepalive_connections=24),
                )
    return _shared_client


def _connect_error_envelope() -> dict:
    return {
        "error": f"Cannot connect to Burp extension at {BASE_URL}. Is the extension loaded?",
        "code": "extension_unreachable",
        "hint": "Open Burp, ensure the Swiss-Knife extension is loaded, then retry.",
    }


def _http_status_envelope(e: httpx.HTTPStatusError) -> dict:
    """Preserve Java-side {error, code, hint} envelope when present."""
    body = e.response.text
    try:
        parsed = e.response.json()
        if isinstance(parsed, dict) and "error" in parsed:
            # Java already returned a structured envelope — pass through
            return {
                "error": parsed.get("error", body),
                "code": parsed.get("code", f"http_{e.response.status_code}"),
                "hint": parsed.get("hint", ""),
            }
    except Exception:
        pass
    return {
        "error": f"HTTP {e.response.status_code}: {body}",
        "code": f"http_{e.response.status_code}",
        "hint": "",
    }


def _generic_exception_envelope(e: Exception) -> dict:
    """Shared fallback envelope for unexpected httpx/client errors.

    str(e) is empty for some httpx exceptions (ReadTimeout('') / ConnectTimeout)
    — always include the class name so the operator gets actionable text.
    """
    detail = str(e) or "(no detail)"
    cls = type(e).__name__
    hint = ""
    if "Timeout" in cls:
        hint = (
            f"Burp extension didn't respond within {BURP_API_TIMEOUT}s. "
            "The Java side may still be waiting on the target — "
            "raise BURP_API_TIMEOUT or shorten the target's read window."
        )
    elif "Connect" in cls:
        hint = "Verify the Burp extension is loaded and listening on BURP_API_PORT."
    return {"error": f"{cls}: {detail}", "code": "client_exception", "hint": hint}


async def get(path: str, params: dict | None = None) -> dict:
    """GET request to the Burp extension REST API."""
    try:
        client = await _get_client()
        resp = await client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return _generic_exception_envelope(e)


async def post(path: str, json: dict | None = None) -> dict:
    """POST request to the Burp extension REST API."""
    try:
        client = await _get_client()
        resp = await client.post(path, json=json or {})
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return _generic_exception_envelope(e)


async def delete(path: str) -> dict:
    """Send DELETE request to the Burp extension API."""
    try:
        client = await _get_client()
        resp = await client.delete(path)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return _generic_exception_envelope(e)


async def aclose() -> None:
    """Close the shared client (called on shutdown)."""
    global _shared_client
    if _shared_client is not None:
        await _shared_client.aclose()
        _shared_client = None


async def check_scope(url: str) -> dict:
    """Returns {'in_scope': bool} or {'error': ...}. Wraps POST /api/scope/check."""
    return await post("/api/scope/check", json={"url": url})


async def get_session_last_host(name: str) -> dict:
    """Returns {'host', 'port', 'https'} or {'error': ...}. Wraps GET /api/session/{name}/last-host."""
    return await get(f"/api/session/{name}/last-host")
