"""Edge-case test: test_cors."""


from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict


async def test_cors_impl(
    session: str,
    path: str = "/",
    test_origins: list[str] | None = None,
) -> dict:
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

    human = "\n".join(lines)
    critical_hits = sum(1 for v in vulns if v.startswith("CRITICAL"))
    if critical_hits >= 1:
        verdict, confidence = "CONFIRMED", 0.85
        ev = f"CORS misconfig: {critical_hits} CRITICAL hit(s) (wildcard/reflected + credentials)"
    elif vulns:
        verdict, confidence = "SUSPECTED", 0.55
        ev = f"CORS misconfig: {len(vulns)} hit(s) — operator review per item"
    else:
        verdict, confidence = "FAILED", 0.1
        ev = "no CORS misconfiguration detected"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="cors",
        details={"path": path, "vulnerabilities": vulns},
        summary=human,
    )
