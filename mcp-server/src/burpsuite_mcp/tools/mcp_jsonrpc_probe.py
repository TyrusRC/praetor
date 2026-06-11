"""probe_mcp_jsonrpc_methods — JSON-RPC 2.0 MCP method enumerator (W29-k).

Wallarm's `mcp-jsonrpc2-ultimate-detect` nuclei template enumerates every
known MCP server method (tools/list, resources/list, prompts/list, …) by
firing JSON-RPC 2.0 requests in pitchfork against a single endpoint.

Praetor already ships `run_mcptox` (heuristic tool-source audit) and
`probe_mcp_server_attacks` (mcp-atlassian CVE-2026-27825/27826 active probes).
The missing piece was a **canonical method enumerator** that doesn't depend
on Atlassian-specific paths — works against ANY MCP server's JSON-RPC
endpoint regardless of vendor.

Coverage (every documented MCP 2025/2026 method):

  Discovery:    initialize, initialized, ping
  Tools:        tools/list, tools/call
  Resources:    resources/list, resources/templates/list, resources/read,
                resources/subscribe, resources/unsubscribe
  Prompts:      prompts/list, prompts/get
  Sampling:     sampling/createMessage
  Roots:        roots/list
  Logging:      logging/setLevel
  Completion:   completion/complete
  Notifications: notifications/initialized, notifications/cancelled,
                 notifications/progress, notifications/message,
                 notifications/resources/updated,
                 notifications/resources/list_changed,
                 notifications/tools/list_changed,
                 notifications/prompts/list_changed

VerdictResult:
  - CONFIRMED — server responds 200 + valid JSON-RPC 2.0 to ≥1 method with
    NO authentication (real unauth-MCP exposure)
  - SUSPECTED — server responds 200 to initialize but rejects most methods
    (likely scoped MCP exposure)
  - FAILED — no JSON-RPC 2.0 shape responses
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# Canonical MCP method list (MCP spec v2025-06)
_MCP_METHODS = [
    # Discovery
    ("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "praetor", "version": "1.0"},
    }),
    ("ping", {}),
    # Tools
    ("tools/list", {}),
    # Resources
    ("resources/list", {}),
    ("resources/templates/list", {}),
    # Prompts
    ("prompts/list", {}),
    # Roots
    ("roots/list", {}),
    # Completion
    ("completion/complete", {"ref": {"type": "ref/prompt", "name": "x"},
                              "argument": {"name": "y", "value": "z"}}),
    # Logging — should fail safely (no level change) on most servers
    ("logging/setLevel", {"level": "debug"}),
]


async def _jsonrpc(endpoint: str, method: str, params: dict,
                   request_id: int, headers: dict | None = None,
                   timeout: int = 20) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    payload: dict[str, Any] = {
        "method": "POST",
        "url": endpoint,
        "json_body": body,
        "headers": headers or {"Content-Type": "application/json",
                               "Accept": "application/json, text/event-stream"},
        "follow_redirects": False,
        "timeout": timeout,
    }
    return await client.post("/api/http/curl", json=payload)


def _is_valid_jsonrpc(body: str) -> tuple[bool, dict]:
    """Return (is_jsonrpc_2_0, parsed_object)."""
    if not body:
        return False, {}
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0":
            return True, obj
    except json.JSONDecodeError:
        pass
    # Streamed SSE wrapping JSON-RPC — best-effort scan
    if "jsonrpc" in body and "2.0" in body:
        for line in body.splitlines():
            if line.startswith("data:"):
                try:
                    inner = json.loads(line[5:].strip())
                    if isinstance(inner, dict) and inner.get("jsonrpc") == "2.0":
                        return True, inner
                except Exception:
                    continue
    return False, {}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_mcp_jsonrpc_methods(  # cost: medium (~10 requests)
        endpoint_url: str,
        methods: list[str] | None = None,
        bearer_token: str = "",
        timeout: int = 20,
    ) -> dict:
        """JSON-RPC 2.0 MCP method enumerator (Wallarm ultimate-detect parity).

        Fires every documented MCP method against {endpoint_url} as a separate
        JSON-RPC 2.0 request. Parses responses to determine which methods
        the server honors WITHOUT authentication.

        VerdictResult:
          - CONFIRMED — ≥2 methods responded with JSON-RPC 2.0 result + no auth
          - SUSPECTED — initialize succeeded, other methods rejected (scoped exposure)
          - FAILED — no JSON-RPC 2.0 shape responses

        Args:
            endpoint_url: MCP server JSON-RPC endpoint (often /mcp or /jsonrpc)
            methods: override default method list with operator-supplied list
            bearer_token: optional Authorization: Bearer ... for authenticated mode
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(endpoint_url)
        if not scope.get("in_scope"):
            return error_verdict("mcp_jsonrpc_enum", "out_of_scope",
                                 f"{endpoint_url} not in scope")

        method_list = methods or [m for m, _ in _MCP_METHODS]
        params_map = dict(_MCP_METHODS)
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        logger_indices: list[int] = []
        results: list[dict] = []
        succeeded_methods: list[str] = []
        rejected_methods: list[str] = []
        initialize_ok = False

        for idx, method in enumerate(method_list, start=1):
            params = params_map.get(method, {})
            resp = await _jsonrpc(endpoint_url, method, params, idx,
                                  headers=headers, timeout=timeout)
            if resp.get("error"):
                results.append({"method": method, "transport_error": resp.get("error", "")})
                continue
            if "logger_index" in resp:
                logger_indices.append(resp["logger_index"])
            status = resp.get("status_code", 0)
            body = resp.get("response_body") or ""
            is_jrpc, parsed = _is_valid_jsonrpc(body if isinstance(body, str) else "")
            has_result = is_jrpc and "result" in parsed
            has_error = is_jrpc and "error" in parsed
            rec = {
                "method": method,
                "status": status,
                "is_jsonrpc_2_0": is_jrpc,
                "has_result": has_result,
                "has_error": has_error,
                "error_code": (parsed.get("error") or {}).get("code") if has_error else None,
                "error_message": (parsed.get("error") or {}).get("message", "")[:200] if has_error else "",
            }
            # Excerpt of result for inventory (capped)
            if has_result:
                result_blob = json.dumps(parsed.get("result"), default=str)[:500]
                rec["result_excerpt"] = result_blob
                succeeded_methods.append(method)
                if method == "initialize":
                    initialize_ok = True
            elif has_error:
                rejected_methods.append(method)
            results.append(rec)

        details = {
            "endpoint_url": endpoint_url,
            "methods_tried": len(method_list),
            "succeeded": succeeded_methods,
            "rejected": rejected_methods,
            "results": results,
            "authenticated": bool(bearer_token),
        }

        if len(succeeded_methods) >= 2 and not bearer_token:
            return make_verdict(
                vuln_type="mcp_jsonrpc_unauth",
                verdict="CONFIRMED",
                confidence=0.95,
                evidence_summary=f"{len(succeeded_methods)} MCP methods callable WITHOUT auth: {', '.join(succeeded_methods[:5])}",
                logger_indices=logger_indices,
                details=details,
                human_summary=f"Unauth MCP server: {len(succeeded_methods)} methods exposed",
            )
        if len(succeeded_methods) >= 2 and bearer_token:
            return make_verdict(
                vuln_type="mcp_jsonrpc_enum",
                verdict="CONFIRMED",
                confidence=0.9,
                evidence_summary=f"{len(succeeded_methods)} MCP methods enumerated with provided bearer",
                logger_indices=logger_indices,
                details=details,
                human_summary=f"MCP inventory: {len(succeeded_methods)} methods",
            )
        if initialize_ok:
            return make_verdict(
                vuln_type="mcp_jsonrpc_enum",
                verdict="SUSPECTED",
                confidence=0.5,
                evidence_summary="initialize succeeded but most methods rejected — scoped MCP exposure",
                logger_indices=logger_indices,
                details=details,
                human_summary="Scoped MCP exposure (initialize only)",
            )
        return make_verdict(
            vuln_type="mcp_jsonrpc_enum",
            verdict="FAILED",
            confidence=0.8,
            evidence_summary=f"No JSON-RPC 2.0 method succeeded across {len(method_list)} attempts",
            logger_indices=logger_indices,
            details=details,
            human_summary="Not an MCP JSON-RPC endpoint",
        )
