import httpx
from burpsuite_mcp.config import BASE_URL, BURP_API_TIMEOUT


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=BASE_URL, timeout=BURP_API_TIMEOUT)


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


async def get(path: str, params: dict | None = None) -> dict:
    """GET request to the Burp extension REST API."""
    try:
        async with _client() as client:
            resp = await client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return {"error": str(e), "code": "client_exception", "hint": ""}


async def post(path: str, json: dict | None = None) -> dict:
    """POST request to the Burp extension REST API."""
    try:
        async with _client() as client:
            resp = await client.post(path, json=json or {})
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return {"error": str(e), "code": "client_exception", "hint": ""}


async def delete(path: str) -> dict:
    """Send DELETE request to the Burp extension API."""
    try:
        async with _client() as c:
            resp = await c.delete(path)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return _connect_error_envelope()
    except httpx.HTTPStatusError as e:
        return _http_status_envelope(e)
    except Exception as e:
        return {"error": str(e), "code": "client_exception", "hint": ""}


async def check_scope(url: str) -> dict:
    """Returns {'in_scope': bool} or {'error': ...}. Wraps POST /api/scope/check."""
    return await post("/api/scope/check", json={"url": url})


async def get_session_last_host(name: str) -> dict:
    """Returns {'host', 'port', 'https'} or {'error': ...}. Wraps GET /api/session/{name}/last-host."""
    return await get(f"/api/session/{name}/last-host")
