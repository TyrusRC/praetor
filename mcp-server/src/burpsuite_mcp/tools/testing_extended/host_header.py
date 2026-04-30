"""test_host_header — Host / X-Forwarded-Host / X-Original-URL injection probes."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import (
    resolve_host_from,
    scope_or_error,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_host_header(session: str, path: str = "/") -> str:
        """Test Host header injection via alternate host, X-Forwarded-Host, X-Original-URL, and variants.

        Args:
            session: Session name for auth state
            path: Endpoint path to test (default /)
        """
        lines = [f"Host Header Injection Tests: {path}\n"]
        findings = []

        baseline = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        if "error" in baseline:
            return f"Error getting baseline: {baseline['error']}"
        baseline_body = baseline.get("response_body", "")
        baseline_status = baseline.get("status", 0)

        host, port, is_https, err = await resolve_host_from(baseline.get("url", ""), session)
        if err:
            return f"Error: {err}"
        scope_err = await scope_or_error(host, is_https, port)
        if scope_err:
            return scope_err
        scheme = "https" if is_https else "http"
        authority = host if (is_https and port == 443) or (not is_https and port == 80) else f"{host}:{port}"
        target_url = f"{scheme}://{authority}{path}"

        tests = [
            ("Alternate Host", {"Host": "evil.com"}, "evil.com"),
            ("X-Forwarded-Host", {"X-Forwarded-Host": "evil.com"}, "evil.com"),
            ("X-Forwarded-For + Host", {"X-Forwarded-Host": "evil.com", "X-Forwarded-For": "127.0.0.1"}, "evil.com"),
            ("X-Original-URL", {"X-Original-URL": "/admin"}, "/admin"),
            ("X-Rewrite-URL", {"X-Rewrite-URL": "/admin"}, "/admin"),
        ]

        for test_name, headers, check_value in tests:
            resp = await client.post("/api/http/send", json={
                "method": "GET",
                "url": target_url,
                "headers": headers,
            })
            if "error" in resp:
                lines.append(f"  [{test_name}] Error: {resp['error']}")
                continue

            body = resp.get("response_body", resp.get("body", ""))
            status = resp.get("status_code", resp.get("status", 0))

            reflected_body = check_value.lower() in body.lower() and check_value.lower() not in baseline_body.lower()

            reflected_header = False
            location = ""
            for h in resp.get("response_headers", resp.get("headers", [])):
                hname = h.get("name", "").lower() if isinstance(h, dict) else ""
                hval = h.get("value", "") if isinstance(h, dict) else ""
                if check_value.lower() in hval.lower():
                    reflected_header = True
                    location = f"{hname}: {hval}"

            flags = []
            if reflected_body:
                flags.append("REFLECTED_IN_BODY")
            if reflected_header:
                flags.append(f"REFLECTED_IN_HEADER({location})")
            if status != baseline_status:
                flags.append(f"STATUS_CHANGE:{status}")

            if flags:
                findings.append((test_name, flags))
                flag_str = " ".join(f"[!{f}]" for f in flags)
                lines.append(f"  [{test_name}] {flag_str}")
                if reflected_body:
                    idx = body.lower().find(check_value.lower())
                    start = max(0, idx - 50)
                    end = min(len(body), idx + len(check_value) + 50)
                    lines.append(f"    Body context: ...{body[start:end]}...")
            else:
                lines.append(f"  [{test_name}] No reflection (status {status})")

        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Findings: {len(findings)}/{len(tests)} tests showed injection")
            for name, flags in findings:
                lines.append(f"  [!] {name}: {', '.join(flags)}")
            lines.append("\nRisk: Host header reflected — check for cache poisoning, password reset poisoning, or SSRF.")
        else:
            lines.append("No host header injection detected.")

        return "\n".join(lines)
