"""probe_sse_injection — Server-Sent Events injection (W29-g).

The sse_injection KB has shipped since W7 but no active tool consumed it.
Operator-driven probes only — now packaged as a turnkey tool.

SSE injection works when a server reflects user-supplied input into a
text/event-stream response without filtering newlines. Newlines split SSE
records (`\n\n`), so an attacker can inject:
  - Fake `event: <name>` lines → trigger arbitrary event types
  - Fake `data: <payload>` lines → cause client JS to act on attacker data
  - Fake `id: <large>` lines → poison Last-Event-ID replay state

Probe sequence:
  1. Confirm the endpoint returns text/event-stream
  2. Inject newline-encoded payload through the operator-named parameter
  3. Read response body, look for KB-defined markers (swk-injected event:,
     admin data:, large id:) and Content-Type confirmation
  4. Verdict CONFIRMED on marker match + correct Content-Type;
     SUSPECTED on marker match without confirmed event-stream Content-Type
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# KB-aligned probes (sse_injection.json)
_PROBES = [
    {
        "name": "event_injection",
        "payload": "swktest\n\nevent: swk-injected\ndata: PRAETOR-CANARY\n\n",
        "markers": ("swk-injected", "event: swk-injected"),
        "severity": "medium",
    },
    {
        "name": "data_field_injection",
        "payload": 'swktest\ndata: {"admin":true}\n\n',
        "markers": ('"admin":true', 'data: {"admin'),
        "severity": "high",
    },
    {
        "name": "id_replay_poison",
        "payload": "swktest\nid: 99999999\n\n",
        "markers": ("id: 99999999",),
        "severity": "medium",
    },
    {
        "name": "retry_injection",
        "payload": "swktest\nretry: 100\n\n",
        "markers": ("retry: 100",),
        "severity": "low",
    },
]


def _is_event_stream(resp: dict) -> bool:
    hdrs = {k.lower(): str(v).lower() for k, v in (resp.get("response_headers") or {}).items()}
    ctype = hdrs.get("content-type", "")
    return "text/event-stream" in ctype


async def _send(target_url: str, param_name: str, payload: str,
                method: str = "GET", extra_params: dict | None = None,
                timeout: int = 20) -> dict:
    params = {param_name: payload}
    if extra_params:
        params.update(extra_params)
    if method.upper() == "GET":
        sep = "&" if "?" in target_url else "?"
        url = target_url + sep + urlencode(params)
        return await client.post("/api/http/curl", json={
            "method": "GET", "url": url, "timeout": timeout,
            "headers": {"Accept": "text/event-stream"},
        })
    return await client.post("/api/http/curl", json={
        "method": method, "url": target_url,
        "body": urlencode(params),
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/event-stream",
        },
        "timeout": timeout,
    })


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_sse_injection(  # cost: low (4-5 requests)
        target_url: str,
        param_name: str,
        method: str = "GET",
        extra_params: dict | None = None,
        timeout: int = 20,
    ) -> dict:
        """Active probe for SSE (text/event-stream) newline-injection.

        Args:
            target_url: SSE endpoint to test
            param_name: user-controlled parameter to inject into (e.g. 'message')
            method: GET or POST
            extra_params: any other parameters required (e.g. 'channel')
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(target_url)
        if not scope.get("in_scope"):
            return error_verdict("sse_injection", "out_of_scope",
                                 f"{target_url} not in scope")

        # First confirm the endpoint returns text/event-stream with control data
        baseline = await _send(target_url, param_name, "control",
                               method=method, extra_params=extra_params,
                               timeout=timeout)
        if baseline.get("error"):
            return error_verdict("sse_injection", "baseline_failed",
                                 baseline.get("error", ""))
        logger_indices: list[int] = []
        if "logger_index" in baseline:
            logger_indices.append(baseline["logger_index"])

        baseline_is_sse = _is_event_stream(baseline)
        baseline_body = baseline.get("response_body") or ""

        probe_results = []
        hits: list[dict] = []

        for probe in _PROBES:
            resp = await _send(target_url, param_name, probe["payload"],
                               method=method, extra_params=extra_params,
                               timeout=timeout)
            if resp.get("error"):
                probe_results.append({"name": probe["name"],
                                      "error": resp.get("error", "")})
                continue
            if "logger_index" in resp:
                logger_indices.append(resp["logger_index"])
            body = resp.get("response_body") or ""
            is_sse = _is_event_stream(resp)
            matched = [m for m in probe["markers"] if m in body]
            rec = {
                "name": probe["name"],
                "severity": probe["severity"],
                "is_sse": is_sse,
                "markers_matched": matched,
                "status": resp.get("status_code", 0),
            }
            probe_results.append(rec)
            if matched:
                hits.append(rec)

        confirmed_hits = [h for h in hits if h["is_sse"]]
        if confirmed_hits:
            best = confirmed_hits[0]
            return make_verdict(
                vuln_type="sse_injection",
                verdict="CONFIRMED",
                confidence=0.9,
                evidence_summary=f"{len(confirmed_hits)} variant(s) injected with text/event-stream content-type",
                logger_indices=logger_indices,
                details={
                    "target_url": target_url,
                    "param_name": param_name,
                    "confirmed": confirmed_hits,
                    "all_probes": probe_results,
                },
                human_summary=f"SSE injection confirmed via {best['name']}",
            )
        if hits:
            return make_verdict(
                vuln_type="sse_injection",
                verdict="SUSPECTED",
                confidence=0.55,
                evidence_summary=f"{len(hits)} variant(s) reflected payload markers but content-type ≠ text/event-stream",
                logger_indices=logger_indices,
                details={
                    "target_url": target_url,
                    "hits": hits,
                    "all_probes": probe_results,
                    "baseline_is_sse": baseline_is_sse,
                },
                human_summary=f"SSE injection SUSPECTED — reflection without event-stream content-type",
            )
        if not baseline_is_sse:
            return make_verdict(
                vuln_type="sse_injection",
                verdict="FAILED",
                confidence=0.7,
                evidence_summary="Endpoint does not return text/event-stream — not an SSE endpoint",
                logger_indices=logger_indices,
                details={"baseline_content_type": (baseline.get("response_headers") or {}).get("content-type", "")},
                human_summary="Not an SSE endpoint",
            )
        return make_verdict(
            vuln_type="sse_injection",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary=f"All {len(_PROBES)} variants rejected — server filters newlines correctly",
            logger_indices=logger_indices,
            details={"all_probes": probe_results},
            human_summary="SSE filters newline injection",
        )
