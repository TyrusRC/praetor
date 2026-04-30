"""test_crlf_injection — CRLF / response-splitting probes for path or query parameter."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import scope_or_error


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_crlf_injection(session: str, path: str, parameter: str = "") -> str:
        """Test for CRLF injection and HTTP response splitting in URL path or parameters.

        Args:
            session: Session name for auth state
            path: Target endpoint path
            parameter: Parameter to inject into (tests path if empty)
        """
        payloads = [
            ("%0d%0aInjected-Header:true", "Injected-Header"),
            ("%0d%0aSet-Cookie:evil=true", "Set-Cookie"),
            ("%0d%0a%0d%0a<html>INJECTED</html>", "INJECTED"),
            ("\\r\\nInjected-Header:true", "Injected-Header"),
            ("%E5%98%8A%E5%98%8DInjected-Header:true", "Injected-Header"),  # Unicode CRLF
        ]

        host_info = await client.get_session_last_host(session)
        if "error" in host_info:
            return f"Error: {host_info['error']}"
        scope_err = await scope_or_error(host_info["host"], host_info.get("https", True), host_info.get("port", 443))
        if scope_err:
            return scope_err

        lines = [f"CRLF Injection Tests: {path}"]
        if parameter:
            lines[0] += f" [{parameter}]"
        lines.append("")

        findings = []

        for payload, check_str in payloads:
            if parameter:
                test_path = f"{path}?{parameter}={payload}"
            else:
                test_path = f"{path}/{payload}"

            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": test_path,
            })
            if "error" in resp:
                lines.append(f"  Payload {payload[:30]}: Error — {resp['error']}")
                continue

            body = resp.get("response_body", "")
            status = resp.get("status", 0)

            header_injected = False
            for h in resp.get("response_headers", []):
                hname = h.get("name", "") if isinstance(h, dict) else ""
                if "injected" in hname.lower() or (check_str.lower() in hname.lower() and "evil" in h.get("value", "").lower()):
                    header_injected = True
                    break

            body_injected = check_str in body and "<html>" not in body[:100]

            flags = []
            if header_injected:
                flags.append("HEADER_INJECTED")
            if body_injected:
                flags.append("BODY_INJECTED")

            if flags:
                findings.append((payload, flags))
                lines.append(f"  [{', '.join(flags)}] Payload: {payload[:50]}")
                if header_injected:
                    lines.append(f"    Injected header found in response headers!")
                if body_injected:
                    lines.append(f"    Injected content found in response body!")
            else:
                lines.append(f"  [OK] {payload[:40]} — no injection (status {status})")

        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"VULNERABLE — {len(findings)}/{len(payloads)} payloads succeeded")
            lines.append("Risk: CRLF injection can lead to response splitting, XSS, cache poisoning, session fixation.")
        else:
            lines.append("No CRLF injection detected.")

        return "\n".join(lines)
