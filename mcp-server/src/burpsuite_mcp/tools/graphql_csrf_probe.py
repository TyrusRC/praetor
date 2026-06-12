"""GraphQL CSRF probe — Burp 2026.6 parity.

A GraphQL endpoint is CSRF-exploitable when it accepts state-changing
mutations under conditions the browser will send cross-origin without
preflight:

  1. GET /graphql?query=mutation+... — GET-requestable mutation.
  2. POST application/x-www-form-urlencoded — simple request, no preflight.
  3. POST text/plain with query in body — simple request, no preflight.
  4. POST multipart/form-data — simple request, no preflight.

Server SHOULD reject 2-4 for mutations OR require CSRF token OR enforce
Content-Type: application/json. If the server accepts a mutation under
any of 1-4 AND echoes a non-error response, CSRF surface confirmed.

Returns VerdictResult.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_PROBE_MUTATION_DEFAULT = "mutation { __typename }"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_graphql_csrf(
        target_url: str,
        mutation: str = "",
        session: str = "",
    ) -> dict:
        """Test a GraphQL endpoint for CSRF-bypass surface.

        Surface checked:
          - GET-requestable mutation (browser can be tricked via <img src=...>)
          - POST text/plain (no preflight)
          - POST application/x-www-form-urlencoded (no preflight)
          - POST multipart/form-data (no preflight)

        Each variant sends the supplied mutation (default `mutation {{ __typename }}`
        which is benign). Server response is checked for GraphQL response shape
        (presence of `data` or `errors` keys) AND absence of CSRF-related
        rejection markers.

        Args:
            target_url: full GraphQL endpoint URL (e.g. https://app/graphql).
            mutation: GraphQL operation string. Defaults to a benign
                __typename query. Operator can pass a more diagnostic mutation
                (e.g. `mutation { logout }`) BUT must be benign per Rule 5.
            session: optional session name for authenticated probing.

        Returns: VerdictResult — CONFIRMED if any non-JSON variant returns a
        valid GraphQL response shape; SUSPECTED if server returns 200 but
        rejection text; FAILED if every non-JSON variant 4xx/415s.
        """
        if not target_url:
            return error_verdict("target_url required", vuln_type="graphql_csrf")

        op = mutation or _PROBE_MUTATION_DEFAULT
        op_quoted = json.dumps(op)  # JSON-safe string

        variants = [
            ("get_url_param", {
                "method": "GET",
                "url": f"{target_url}?query={_urlencode(op)}",
                "headers": {},
                "body": "",
            }),
            ("post_text_plain", {
                "method": "POST",
                "url": target_url,
                "headers": {"Content-Type": "text/plain"},
                "body": json.dumps({"query": op}),
            }),
            ("post_form_urlencoded", {
                "method": "POST",
                "url": target_url,
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": f"query={_urlencode(op)}",
            }),
            ("post_multipart_form", {
                "method": "POST",
                "url": target_url,
                "headers": {"Content-Type": "multipart/form-data; boundary=----GqlCsrf"},
                "body": (
                    "------GqlCsrf\r\n"
                    'Content-Disposition: form-data; name="query"\r\n\r\n'
                    f"{op}\r\n"
                    "------GqlCsrf--\r\n"
                ),
            }),
        ]

        # Baseline — application/json POST should ALWAYS work (canonical GraphQL).
        baseline = await _send_request(target_url, "POST", {
            "Content-Type": "application/json",
        }, json.dumps({"query": op}), session)
        if "error" in baseline:
            return error_verdict(
                f"baseline JSON POST failed: {baseline['error']}",
                vuln_type="graphql_csrf",
            )

        baseline_status = baseline.get("status_code") or baseline.get("status")
        baseline_body = baseline.get("response_body", "") or ""
        baseline_logger = baseline.get("logger_index", -1)
        baseline_is_graphql = _is_graphql_response(baseline_body)

        reproductions: list[dict] = [{
            "label": "baseline_json_post",
            "status_code": baseline_status,
            "logger_index": baseline_logger,
            "graphql_shape": baseline_is_graphql,
        }]

        if not baseline_is_graphql:
            return make_verdict(
                "FAILED",
                0.10,
                "Baseline application/json POST did not return a GraphQL "
                f"response shape (status={baseline_status}) — target may not be GraphQL",
                vuln_type="graphql_csrf",
                logger_indices=[baseline_logger] if baseline_logger >= 0 else [],
                reproductions=reproductions,
                summary=f"FAILED — {target_url} did not behave as a GraphQL endpoint",
            )

        csrf_surface: list[str] = []
        rejection_only: list[str] = []
        logger_indices = [baseline_logger] if baseline_logger >= 0 else []

        for label, opts in variants:
            method = opts["method"]
            resp = await _send_request(
                opts["url"], method, opts["headers"], opts["body"], session,
            )
            status = resp.get("status_code") or resp.get("status")
            body = resp.get("response_body", "") or ""
            logger_idx = resp.get("logger_index", -1)
            if isinstance(logger_idx, int) and logger_idx >= 0:
                logger_indices.append(logger_idx)
            is_gql = _is_graphql_response(body)
            entry = {
                "label": label,
                "status_code": status,
                "logger_index": logger_idx,
                "graphql_shape": is_gql,
            }
            reproductions.append(entry)
            if is_gql and status in (200, 400):
                csrf_surface.append(label)
            elif status == 200:
                rejection_only.append(label)

        if csrf_surface:
            return make_verdict(
                "CONFIRMED",
                0.85,
                f"GraphQL CSRF surface — endpoint accepts mutations via "
                f"{len(csrf_surface)} preflight-bypassing variant(s): "
                f"{csrf_surface}. CSRF possible without origin restriction.",
                vuln_type="graphql_csrf",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"csrf_variants": csrf_surface},
                summary=(
                    f"CONFIRMED GraphQL CSRF on {target_url}: "
                    f"{', '.join(csrf_surface)}"
                ),
            )

        if rejection_only:
            return make_verdict(
                "SUSPECTED",
                0.45,
                "Endpoint returns 200 on non-JSON variants but does not echo a "
                "GraphQL response shape — may be silently dropping the query, "
                "manual review recommended",
                vuln_type="graphql_csrf",
                logger_indices=logger_indices,
                reproductions=reproductions,
                summary=f"SUSPECTED — soft accept on non-JSON CT for {target_url}",
            )

        return make_verdict(
            "FAILED",
            0.15,
            "GraphQL endpoint correctly rejected all non-JSON Content-Types — "
            "no CSRF surface via preflight bypass",
            vuln_type="graphql_csrf",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no CSRF surface on {target_url}",
        )


def _urlencode(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


def _is_graphql_response(body: str) -> bool:
    """True if body parses as JSON containing 'data' or 'errors' (GraphQL spec)."""
    if not body:
        return False
    try:
        obj = json.loads(body[:32768])
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(obj, dict):
        return False
    return "data" in obj or "errors" in obj


async def _send_request(
    url: str, method: str, headers: dict, body: str, session: str,
) -> dict:
    """Route via session if provided, else Burp curl. Headers as dict → list-of-dict."""
    header_list = [{"name": k, "value": v} for k, v in headers.items()]
    if session:
        payload: dict = {
            "session": session,
            "method": method,
            "url": url,
            "headers": header_list,
        }
        if body:
            payload["body"] = body
        return await client.post("/api/session/request", json=payload)
    payload = {
        "url": url,
        "method": method,
        "headers": header_list,
    }
    if body:
        payload["data"] = body
    return await client.post("/api/http/curl", json=payload)
