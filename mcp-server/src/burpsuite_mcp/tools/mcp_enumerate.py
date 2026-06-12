"""enumerate_mcp_server — ZAP May 2026 parity.

Performs the standard MCP JSON-RPC 2.0 handshake against a target endpoint
and inventories tools / resources / prompts. Complements probe_mcp_jsonrpc_methods
(which fires arbitrary methods + judges) by providing the canonical
discovery flow with structured inventory output.

Steps:
  1. initialize — protocolVersion, clientInfo, capabilities
  2. notifications/initialized (no response expected)
  3. tools/list → [{name, description, inputSchema}, ...]
  4. resources/list → [{uri, name, mimeType}, ...]
  5. prompts/list → [{name, description, arguments}, ...]

Every request lands in Burp proxy history (Rule 26a) with logger_index
returned in the inventory entry for later cross-reference.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_DEFAULT_PROTOCOL_VERSION = "2025-06-18"
_DEFAULT_CLIENT_INFO = {"name": "praetor", "version": "1.0"}
_DEFAULT_CAPABILITIES = {"roots": {"listChanged": True}, "sampling": {}}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def enumerate_mcp_server(
        endpoint_url: str,
        bearer_token: str = "",
        protocol_version: str = _DEFAULT_PROTOCOL_VERSION,
        timeout: int = 20,
    ) -> dict:
        """Standard MCP JSON-RPC 2.0 discovery handshake.

        Runs the full canonical flow against an MCP server endpoint:
        initialize → tools/list → resources/list → prompts/list. Returns
        structured inventory with logger_index per request so the operator
        can cross-reference with proxy history.

        Args:
            endpoint_url: MCP JSON-RPC endpoint URL (commonly /mcp,
                /api/mcp, or /jsonrpc).
            bearer_token: optional Authorization: Bearer token for
                authenticated discovery.
            protocol_version: MCP protocol version to advertise
                (default: 2025-06-18 — current spec).
            timeout: per-request timeout (s).

        Returns:
            {
              "endpoint": str,
              "initialized": bool,
              "server_info": dict | None,
              "server_capabilities": dict | None,
              "tools": [{name, description, input_schema_summary, logger_index}],
              "resources": [{uri, name, mime_type, logger_index}],
              "prompts": [{name, description, arg_count, logger_index}],
              "logger_indices": [int, ...],   # every request, in order
              "errors": {step: str},
              "summary": str,
            }
        """
        if not endpoint_url:
            return {"error": "endpoint_url required"}

        result: dict[str, Any] = {
            "endpoint": endpoint_url,
            "initialized": False,
            "server_info": None,
            "server_capabilities": None,
            "tools": [],
            "resources": [],
            "prompts": [],
            "logger_indices": [],
            "errors": {},
        }
        headers = _build_headers(bearer_token)

        # Step 1 — initialize
        init_resp = await _jsonrpc(endpoint_url, "initialize", {
            "protocolVersion": protocol_version,
            "clientInfo": _DEFAULT_CLIENT_INFO,
            "capabilities": _DEFAULT_CAPABILITIES,
        }, request_id=1, headers=headers, timeout=timeout)
        init_logger = init_resp.get("logger_index", -1)
        if isinstance(init_logger, int) and init_logger >= 0:
            result["logger_indices"].append(init_logger)

        if "error" in init_resp:
            result["errors"]["initialize"] = init_resp["error"]
            result["summary"] = f"initialize failed: {init_resp['error']}"
            return result

        init_obj = _parse_jsonrpc_body(init_resp.get("response_body", "") or "")
        if init_obj and "result" in init_obj:
            r = init_obj["result"]
            result["initialized"] = True
            result["server_info"] = r.get("serverInfo")
            result["server_capabilities"] = r.get("capabilities")
        elif init_obj and "error" in init_obj:
            result["errors"]["initialize"] = init_obj["error"].get("message", "jsonrpc error")
            result["summary"] = f"initialize rejected by server: {result['errors']['initialize']}"
            return result
        else:
            result["errors"]["initialize"] = "non-jsonrpc response"
            result["summary"] = "initialize returned non-JSON-RPC body"
            return result

        # Step 2 — notifications/initialized (fire-and-forget; no response expected)
        await _jsonrpc(endpoint_url, "notifications/initialized", {},
                       request_id=None, headers=headers, timeout=timeout,
                       is_notification=True)

        # Step 3 — tools/list
        await _enumerate_step(
            endpoint_url, "tools/list", _summarise_tool,
            "tools", result, headers, timeout, request_id=2,
        )

        # Step 4 — resources/list
        await _enumerate_step(
            endpoint_url, "resources/list", _summarise_resource,
            "resources", result, headers, timeout, request_id=3,
        )

        # Step 5 — prompts/list
        await _enumerate_step(
            endpoint_url, "prompts/list", _summarise_prompt,
            "prompts", result, headers, timeout, request_id=4,
        )

        result["summary"] = (
            f"MCP server initialized — "
            f"tools={len(result['tools'])}, "
            f"resources={len(result['resources'])}, "
            f"prompts={len(result['prompts'])}. "
            f"Server: {(result['server_info'] or {}).get('name', '?')} "
            f"{(result['server_info'] or {}).get('version', '?')}."
        )
        return result


async def _enumerate_step(
    endpoint_url: str, method: str, summariser,
    key: str, result: dict, headers: dict, timeout: int, request_id: int,
) -> None:
    """Run one list endpoint and accumulate summarised entries."""
    resp = await _jsonrpc(endpoint_url, method, {}, request_id=request_id,
                          headers=headers, timeout=timeout)
    logger_idx = resp.get("logger_index", -1)
    if isinstance(logger_idx, int) and logger_idx >= 0:
        result["logger_indices"].append(logger_idx)

    if "error" in resp:
        result["errors"][method] = resp["error"]
        return

    obj = _parse_jsonrpc_body(resp.get("response_body", "") or "")
    if not obj or "result" not in obj:
        result["errors"][method] = "non-jsonrpc or missing result"
        return

    raw_items = obj["result"].get(key, [])
    if isinstance(raw_items, list):
        for item in raw_items:
            if isinstance(item, dict):
                summary = summariser(item)
                summary["logger_index"] = logger_idx
                result[key].append(summary)


def _summarise_tool(item: dict) -> dict:
    schema = item.get("inputSchema") or {}
    props = schema.get("properties") or {}
    return {
        "name": item.get("name", ""),
        "description": (item.get("description") or "")[:240],
        "input_schema_summary": {
            "required": schema.get("required", []),
            "param_names": list(props.keys())[:20],
        },
    }


def _summarise_resource(item: dict) -> dict:
    return {
        "uri": item.get("uri", ""),
        "name": item.get("name", ""),
        "mime_type": item.get("mimeType", ""),
        "description": (item.get("description") or "")[:160],
    }


def _summarise_prompt(item: dict) -> dict:
    args = item.get("arguments") or []
    return {
        "name": item.get("name", ""),
        "description": (item.get("description") or "")[:160],
        "arg_count": len(args) if isinstance(args, list) else 0,
        "arg_names": [a.get("name", "") for a in args[:10]] if isinstance(args, list) else [],
    }


def _parse_jsonrpc_body(body: str) -> dict | None:
    """Parse a JSON-RPC 2.0 response body. Handles raw JSON + SSE-wrapped."""
    if not body:
        return None
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0":
            return obj
    except json.JSONDecodeError:
        pass
    # SSE stream variant
    for line in body.splitlines():
        if line.startswith("data:"):
            try:
                inner = json.loads(line[5:].strip())
                if isinstance(inner, dict) and inner.get("jsonrpc") == "2.0":
                    return inner
            except json.JSONDecodeError:
                continue
    return None


def _build_headers(bearer_token: str) -> dict:
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


async def _jsonrpc(
    endpoint: str, method: str, params: dict, request_id: int | None,
    headers: dict, timeout: int, is_notification: bool = False,
) -> dict:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if not is_notification and request_id is not None:
        body["id"] = request_id
    return await client.post("/api/http/curl", json={
        "method": "POST",
        "url": endpoint,
        "json_body": body,
        "headers": headers,
        "follow_redirects": False,
        "timeout": timeout,
    })
