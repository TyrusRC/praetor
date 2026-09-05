"""SSTI request/response helpers."""

from __future__ import annotations

import time
from urllib.parse import quote
from mcp.server.fastmcp import FastMCP
from praetor import client
from praetor.tools.testing._verdict import make_verdict


def _build_request(endpoint: str, parameter: str, method: str, payload: str) -> dict:
    encoded = quote(payload, safe="")
    if method.upper() == "GET":
        sep = "&" if "?" in endpoint else "?"
        return {"method": "GET", "url": f"{endpoint}{sep}{parameter}={encoded}"}
    return {"method": method.upper(), "url": endpoint,
            "data": f"{parameter}={encoded}"}


async def _send(req: dict, session: str) -> dict:
    if session:
        return await client.post("/api/session/request", json={
            "session": session,
            "method": req["method"],
            "path": req["url"],
            "data": req.get("data", ""),
        })
    return await client.post("/api/http/curl", json=req)


def _logger_index(resp: dict) -> int:
    if not isinstance(resp, dict):
        return -1
    return int(resp.get("proxy_index", resp.get("index", resp.get("history_index", -1))))


def _body(resp: dict) -> str:
    if not isinstance(resp, dict):
        return ""
    return (resp.get("response_body") or "")[:50000]


# ─────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────
