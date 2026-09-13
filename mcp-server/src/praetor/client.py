import asyncio

import time
from urllib.parse import urlsplit

import httpx
from praetor.config import BASE_URL, BURP_API_TIMEOUT


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


def _unreachable_hint() -> str:
    """Actionable steps when the REST bridge can't be reached at all.

    Shared by connection-refused (ConnectError) and connect-phase timeout
    (ConnectTimeout) so both point the operator at connectivity, not at Burp
    being slow.
    """
    return (
        f"Can't reach the Praetor REST API. Verify: curl -s {BASE_URL}/api/health . "
        "If that hangs or fails, (re)load the extension in Burp's Extensions tab, "
        "then check its Praetor config-tab Host/Port match BURP_API_HOST/PORT. "
        "On WSL with Burp on Windows the proxy (:8080) can be reachable while the "
        "REST API (:8111) is not — set BURP_API_HOST to the Windows host IP (NAT) "
        "or enable mirrored networking."
    )


def _connect_error_envelope() -> dict:
    return {
        "error": f"Cannot connect to Burp extension at {BASE_URL}. Is the extension loaded?",
        "code": "extension_unreachable",
        "hint": _unreachable_hint(),
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
    # ConnectTimeout is a TimeoutException (NOT a ConnectError), so it slips
    # past the `except httpx.ConnectError` clause and lands here. A connect-
    # phase timeout means the REST bridge is unreachable — raising the read
    # timeout does nothing when nothing is listening — so it gets the
    # connectivity diagnosis, not the "Burp is slow" one.
    if isinstance(e, httpx.ConnectTimeout):
        return {"error": f"{cls}: {detail}", "code": "extension_unreachable",
                "hint": _unreachable_hint()}
    hint = ""
    if isinstance(e, httpx.TimeoutException):
        # ReadTimeout / WriteTimeout / PoolTimeout: connected, but Burp didn't
        # answer in time — raising the timeout is the right lever.
        hint = (
            f"Burp extension didn't respond within {BURP_API_TIMEOUT}s. "
            "The Java side may still be waiting on the target — "
            "raise BURP_API_TIMEOUT or shorten the target's read window."
        )
    elif "Connect" in cls:
        hint = _unreachable_hint()
    return {"error": f"{cls}: {detail}", "code": "client_exception", "hint": hint}


async def get(path: str, params: dict | None = None) -> dict:
    """GET request to the Burp extension REST API."""
    started = time.monotonic()
    try:
        client = await _get_client()
        resp = await client.get(path, params=params)
        resp.raise_for_status()
        out = resp.json()
    except httpx.ConnectError:
        out = _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        out = _http_status_envelope(e)
    except Exception as e:
        out = _generic_exception_envelope(e)
    _log_operation("GET", path, params, out, started)
    return out


async def post(path: str, json: dict | None = None) -> dict:
    """POST request to the Burp extension REST API."""
    started = time.monotonic()
    try:
        client = await _get_client()
        resp = await client.post(path, json=json or {})
        resp.raise_for_status()
        out = resp.json()
    except httpx.ConnectError:
        out = _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        out = _http_status_envelope(e)
    except Exception as e:
        out = _generic_exception_envelope(e)
    _log_operation("POST", path, json, out, started)
    return out


async def delete(path: str) -> dict:
    """Send DELETE request to the Burp extension API."""
    started = time.monotonic()
    try:
        client = await _get_client()
        resp = await client.delete(path)
        resp.raise_for_status()
        out = resp.json()
    except httpx.ConnectError:
        out = _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        out = _http_status_envelope(e)
    except Exception as e:
        out = _generic_exception_envelope(e)
    _log_operation("DELETE", path, None, out, started)
    return out


def _log_operation(verb: str, api: str, payload: dict | None, out: dict, started: float) -> None:
    """Append this call to the operation ledger. Never raises, never blocks.

    Placed here rather than in each tool on purpose: every path that reaches
    Burp — and therefore the target — funnels through these three functions, so
    a tool cannot send traffic without being recorded, and cannot record traffic
    it did not send.
    """
    try:
        from praetor.tools.oplog import _store

        elapsed_ms = int((time.monotonic() - started) * 1000)
        payload = payload if isinstance(payload, dict) else {}
        # The target URL the operation acted on, when there was one. Absent for
        # pure reads of Burp's own state (scope, history, findings).
        url = out.get("url") or payload.get("url") or ""
        entry = {
            "tool": _store_current_tool(),
            "api": f"{verb} {api}",
            "host": urlsplit(url).netloc if url else "",
            "url": _store.redact_url(str(url)) if url else "",
            "method": payload.get("method") or "",
            "status": out.get("status_code"),
            "bytes": out.get("response_length"),
            "elapsed_ms": elapsed_ms,
            "outcome": "error" if "error" in out else "ok",
        }
        if "error" in out:
            entry["error"] = str(out.get("error"))[:200]
        _store.record({k: v for k, v in entry.items() if v not in ("", None)})
    except Exception:
        pass


def _store_current_tool() -> str:
    """Name of the MCP tool driving this call, or '' outside a tool context."""
    try:
        from praetor.tools.oplog import current_tool

        return current_tool.get() or ""
    except Exception:
        return ""


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
