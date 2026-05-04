"""Edge-case test: test_cors."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_cors_impl(
    session: str,
    path: str = "/",
    test_origins: list[str] | None = None,
) -> str:
    """Test CORS configuration for origin reflection and credential misconfigs.

    Args:
        session: Session name
        path: Endpoint path to test
        test_origins: Custom origins to test
    """
    origins = test_origins or [
        "https://evil.com",
        "null",
        "https://evil.target.com",
        "https://target.com.evil.com",
    ]

    lines = [f"CORS Test: {path}\n"]
    vulns = []

    for origin in origins:
        headers = {"Origin": origin}
        resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
            "headers": headers,
        })
        if "error" in resp:
            lines.append(f"  [{origin}] Error: {resp['error']}")
            continue

        # Check response headers for CORS
        acao = ""
        acac = ""
        for h in resp.get("response_headers", []):
            if h["name"].lower() == "access-control-allow-origin":
                acao = h["value"]
            if h["name"].lower() == "access-control-allow-credentials":
                acac = h["value"]

        status = resp.get("status", "?")
        if acao:
            vuln = ""
            # Browsers compare ACAO byte-for-byte with Origin. Substring match
            # would false-positive when ACAO contains a longer legitimate origin
            # (e.g. origin="https://evil.com" vs acao="https://evil.commerce.com").
            if acac.lower() == "true":
                if acao == "*":
                    vuln = "CRITICAL: Wildcard + Credentials"
                    vulns.append(vuln)
                elif acao == origin:
                    vuln = "CRITICAL: Origin reflected + Credentials"
                    vulns.append(vuln)
                elif acao == "null":
                    vuln = "HIGH: Null origin + Credentials"
                    vulns.append(vuln)
            elif acao == origin:
                vuln = "MEDIUM: Origin reflected (no credentials)"
                vulns.append(vuln)

            lines.append(f"  [{origin}] {status} -> ACAO: {acao}, ACAC: {acac} {vuln}")
        else:
            lines.append(f"  [{origin}] {status} -> No CORS headers")

    if vulns:
        lines.append(f"\n*** {len(vulns)} CORS vulnerabilities found ***")
    else:
        lines.append(f"\nNo CORS misconfigurations detected.")

    return "\n".join(lines)
