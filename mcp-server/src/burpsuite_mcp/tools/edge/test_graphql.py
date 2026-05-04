"""Edge-case test: test_graphql."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_graphql_impl(
    session: str,
    path: str = "/graphql",
) -> str:
    """Test GraphQL endpoint for introspection, field suggestions, batch queries, and GET CSRF.

    Args:
        session: Session name
        path: GraphQL endpoint path
    """
    lines = [f"GraphQL Security Test: {path}\n"]
    vulns = []

    # Test 1: Introspection
    introspection_query = '{"query":"{__schema{types{name kind}}}"}'
    resp = await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": introspection_query,
    })
    if "error" not in resp:
        body = resp.get("response_body", "")
        if "__schema" in body and "types" in body:
            vulns.append("HIGH: Introspection enabled — full schema exposed")
            lines.append(f"  [VULN] Introspection: ENABLED (schema leaked)")
        elif resp.get("status") == 200:
            lines.append(f"  [OK] Introspection: Disabled or filtered")
        else:
            lines.append(f"  [?] Introspection: Status {resp.get('status')}")
    else:
        lines.append(f"  [ERR] Introspection: {resp['error']}")

    # Test 2: Field suggestion leakage
    suggestion_query = '{"query":"{userss{id}}"}'
    resp2 = await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": suggestion_query,
    })
    if "error" not in resp2:
        body2 = resp2.get("response_body", "")
        if "did you mean" in body2.lower() or "suggestion" in body2.lower():
            vulns.append("MEDIUM: Field suggestions enabled — schema can be enumerated via typos")
            lines.append(f"  [VULN] Field suggestions: LEAKING schema hints")
        else:
            lines.append(f"  [OK] Field suggestions: Not detected")

    # Test 3: Batch query support
    batch_query = '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
    resp3 = await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": batch_query,
    })
    if "error" not in resp3:
        body3 = resp3.get("response_body", "")
        status3 = resp3.get("status", 0)
        if status3 == 200 and body3.count("__typename") >= 2:
            vulns.append("MEDIUM: Batch queries accepted — potential DoS vector")
            lines.append(f"  [VULN] Batch queries: ACCEPTED (DoS risk)")
        else:
            lines.append(f"  [OK] Batch queries: Not supported or filtered")

    # Test 4: GET-based query (potential CSRF)
    resp4 = await client.post("/api/session/request", json={
        "session": session, "method": "GET",
        "path": f"{path}?query={{__typename}}",
    })
    if "error" not in resp4:
        body4 = resp4.get("response_body", "")
        if "__typename" in body4.lower():
            vulns.append("LOW: GET-based queries accepted — potential CSRF")
            lines.append(f"  [VULN] GET queries: ACCEPTED (CSRF risk)")
        else:
            lines.append(f"  [OK] GET queries: Not accepted")

    if vulns:
        lines.append(f"\n*** {len(vulns)} GraphQL vulnerabilities found ***")
    else:
        lines.append(f"\nNo GraphQL vulnerabilities detected.")

    return "\n".join(lines)
