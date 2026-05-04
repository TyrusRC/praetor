"""Edge-case test: test_jwt."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_jwt_impl(
    token: str,
) -> str:
    """Analyze a JWT token for vulnerabilities and attack vectors.

    Args:
        token: JWT token string
    """
    parts = token.split(".")
    if len(parts) != 3:
        return f"Error: Invalid JWT format (expected 3 parts, got {len(parts)})"

    # Decode header and payload
    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as e:
        return f"Error decoding JWT: {e}"

    lines = ["JWT Analysis:\n"]
    lines.append(f"Header: {json.dumps(header, indent=2)}")
    lines.append(f"Payload: {json.dumps(payload, indent=2)}")

    alg = header.get("alg", "unknown")
    lines.append(f"\nAlgorithm: {alg}")

    # Real findings vs informational hints are tracked separately so the
    # vuln count doesn't lie when there are no actual issues.
    vulns: list[str] = []
    notes: list[str] = []
    tests: list[str] = []

    # alg:none
    if alg.lower() in ("none", ""):
        vulns.append("CRITICAL: Algorithm is 'none' — token has no signature verification")

    # Weak algorithms
    if alg in ("HS256", "HS384", "HS512"):
        notes.append(f"Symmetric algorithm ({alg}) — test with common secrets (secret, password, 123456)")
        # Generate alg:none bypass candidate
        try:
            exp_payload = parts[1]
        except IndexError:
            exp_payload = ""
        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        none_token = f"{none_header}.{exp_payload}."
        tests.append(f"Try alg:none bypass token: {none_token}")

    # RS256 → HS256 confusion
    if alg in ("RS256", "RS384", "RS512"):
        tests.append("Algorithm confusion — try changing to HS256 and sign with public key")

    # JKU/X5U header injection
    if "jku" in header:
        vulns.append(f"HIGH: jku header present ({header['jku']}) — test with attacker-controlled URL")
    if "x5u" in header:
        vulns.append(f"HIGH: x5u header present ({header['x5u']}) — test with attacker-controlled URL")

    # KID injection
    if "kid" in header:
        tests.append(f"kid parameter present ({header['kid']}) — test path traversal: ../../etc/passwd")
        tests.append("kid SQLi: ' UNION SELECT 'key'--")

    # Check payload claims (notes, not vulns)
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            notes.append(f"Token expired (exp: {exp})")
        else:
            remaining = int(exp - time.time())
            notes.append(f"Token expires in {remaining}s")

    if payload.get("admin") or payload.get("role") == "admin":
        tests.append("Token has admin privileges — test with modified non-admin token")

    iss = payload.get("iss", "")
    if iss:
        notes.append(f"Issuer: {iss}")

    if vulns:
        lines.append(f"\nVulnerability Assessment ({len(vulns)}):")
        for v in vulns:
            lines.append(f"  {v}")
    else:
        lines.append("\nNo obvious vulnerabilities in token structure.")

    if tests:
        lines.append(f"\nFollow-up tests ({len(tests)}):")
        for t in tests:
            lines.append(f"  {t}")
    if notes:
        lines.append(f"\nNotes ({len(notes)}):")
        for n in notes:
            lines.append(f"  {n}")

    return "\n".join(lines)
