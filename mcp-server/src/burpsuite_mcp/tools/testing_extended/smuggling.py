"""test_request_smuggling — CL.TE / TE.CL / TE.TE timing probes with replay confirmation."""

import time

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import (
    confirm_timing_anomaly,
    resolve_host_from,
    scope_or_error,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_request_smuggling(session: str, path: str = "/") -> str:
        """Test for HTTP request smuggling (CL.TE and TE.CL) using timing-based detection.
        Uses safe detection payloads only — no destructive testing.

        Example:
            test_request_smuggling(session="s1", path="/")

        Args:
            session: Session name for auth state
            path: Target endpoint path (default /)
        """
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        if "error" in baseline:
            return f"Error: {baseline['error']}"

        target_url = baseline.get("url", "")
        baseline_time = baseline.get("response_time", 0)

        lines = [f"Request Smuggling Tests: {path}\n"]
        lines.append(f"Baseline response time: {baseline_time}ms")
        findings = []

        host, port, is_https, err = await resolve_host_from(target_url, session)
        if err:
            return f"Error: {err}"

        scope_err = await scope_or_error(host, is_https, port)
        if scope_err:
            return scope_err

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
                lines.append(f"  Server rejected malformed request (400) — likely not vulnerable")
            else:
                lines.append(f"  No anomaly detected")

        tete_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
        ]

        lines.append(f"\n--- TE.TE Obfuscation Probes ---")
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

        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Potential smuggling: {', '.join(findings)}")
            lines.append("Recommendation: Verify with repeated timing tests (3+ repetitions). Use Collaborator for confirmation.")
        else:
            lines.append("No request smuggling indicators detected.")

        return "\n".join(lines)
