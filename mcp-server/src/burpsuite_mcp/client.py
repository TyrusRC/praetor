import httpx
from burpsuite_mcp.config import BASE_URL, BURP_API_TIMEOUT


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=BASE_URL, timeout=BURP_API_TIMEOUT)


async def get(path: str, params: dict | None = None) -> dict:
    """GET request to the Burp extension REST API."""
    try:
        async with await _client() as client:
            resp = await client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return {"error": f"Cannot connect to Burp extension at {BASE_URL}. Is the extension loaded?"}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


async def post(path: str, json: dict | None = None) -> dict:
    """POST request to the Burp extension REST API."""
    try:
        async with await _client() as client:
            resp = await client.post(path, json=json or {})
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return {"error": f"Cannot connect to Burp extension at {BASE_URL}. Is the extension loaded?"}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


async def delete(path: str) -> dict:
    """Send DELETE request to the Burp extension API."""
    try:
        async with await _client() as c:
            resp = await c.delete(path)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        return {"error": f"Cannot connect to Burp extension at {BASE_URL}. Is extension loaded?"}
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}
