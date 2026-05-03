"""Tools for Burp Collaborator - out-of-band testing for blind vulnerabilities."""

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# R23: in-process Collaborator pool. Pre-generated subdomains live here
# so OOB-heavy scans (auto_probe, fuzz_parameter with Collaborator-bound
# payloads) can pull from cache instead of one round-trip per probe.
# Concurrent FastMCP tool calls would otherwise race on pop()/append().
_COLLAB_POOL: list[dict] = []
_COLLAB_POOL_LOCK: asyncio.Lock | None = None


def _pool_lock() -> asyncio.Lock:
    global _COLLAB_POOL_LOCK
    if _COLLAB_POOL_LOCK is None:
        _COLLAB_POOL_LOCK = asyncio.Lock()
    return _COLLAB_POOL_LOCK


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_collaborator_payload() -> str:
        """Generate a Burp Collaborator payload URL for out-of-band testing. Requires Burp Professional.

        For batched probing, prefer generate_collaborator_pool(count=N) once at
        session start, then pop_collaborator_payload() per probe (no round-trip).
        """
        # Pull from pool if available — saves a round-trip
        async with _pool_lock():
            entry = _COLLAB_POOL.pop(0) if _COLLAB_POOL else None
            remaining = len(_COLLAB_POOL)
        if entry is not None:
            return (
                f"Collaborator Payload (from pool, {remaining} left):\n"
                f"  Payload URL: {entry.get('payload', '')}\n"
                f"  Interaction ID: {entry.get('interaction_id', '')}\n"
                f"  Server: {entry.get('server', '')}\n\n"
                f"Inject this URL into target parameters, then use get_collaborator_interactions to check for hits."
            )
        data = await client.post("/api/collaborator/payload")
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"Collaborator Payload Generated:\n"
            f"  Payload URL: {data.get('payload', '')}\n"
            f"  Interaction ID: {data.get('interaction_id', '')}\n"
            f"  Server: {data.get('server', '')}\n\n"
            f"Inject this URL into target parameters, then use get_collaborator_interactions to check for hits."
        )

    @mcp.tool()
    async def generate_collaborator_pool(count: int = 25) -> str:
        """Pre-generate a pool of Collaborator subdomains for batched OOB probing (R23).

        Generating one subdomain per probe is wasteful (1 round-trip each).
        Call this once at session start, then generate_collaborator_payload
        will consume from the pool until empty before falling back to network.

        Args:
            count: Number of subdomains to pre-generate (default 25, max 200)
        """
        count = max(1, min(200, count))
        added = 0
        errors = 0
        new_entries: list[dict] = []
        for _ in range(count):
            data = await client.post("/api/collaborator/payload")
            if "error" in data:
                errors += 1
                if errors >= 3:
                    break  # Burp Pro likely missing; stop wasting calls
                continue
            new_entries.append({
                "payload": data.get("payload", ""),
                "interaction_id": data.get("interaction_id", ""),
                "server": data.get("server", ""),
            })
            added += 1
        async with _pool_lock():
            _COLLAB_POOL.extend(new_entries)
            total = len(_COLLAB_POOL)
        return (
            f"Collaborator pool: +{added} subdomains "
            f"(total now {total}, errors={errors})"
        )

    @mcp.tool()
    async def collaborator_pool_status() -> str:
        """Show how many Collaborator subdomains are pre-generated in the pool."""
        return f"Collaborator pool: {len(_COLLAB_POOL)} subdomains available."

    @mcp.tool()
    async def auto_collaborator_test(
        index: int,
        parameter: str,
        injection_point: str = "query",
        poll_seconds: int = 5,
    ) -> str:
        """Inject Collaborator payload into a parameter, send request, and poll for OOB interactions. Requires Burp Professional.

        Args:
            index: Proxy history index of the request to test
            parameter: Parameter name to inject the payload into
            injection_point: Where to inject — 'query', 'body', or 'header'
            poll_seconds: Seconds to wait before polling (default 5, max 15)
        """
        data = await client.post("/api/collaborator/auto-test", json={
            "index": index,
            "parameter": parameter,
            "injection_point": injection_point,
            "poll_seconds": poll_seconds,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        vulnerable = data.get("vulnerable", False)
        interactions = data.get("interactions", [])

        lines = [f"Collaborator Auto-Test Results:\n"]
        lines.append(f"  Payload: {data.get('payload_injected', '')}")
        lines.append(f"  Parameter: {data.get('parameter', '')}")
        lines.append(f"  Injection Point: {data.get('injection_point', '')}")
        lines.append(f"  Response Status: {data.get('response_status', 'N/A')}")
        lines.append(f"  Poll Duration: {data.get('poll_seconds', 0)}s")
        lines.append("")

        if vulnerable:
            lines.append(f"[!!!] VULNERABLE - {len(interactions)} out-of-band interaction(s) detected!")
            lines.append("")
            for interaction in interactions:
                lines.append(f"  [{interaction.get('type')}] from {interaction.get('client_ip')}")
                lines.append(f"    Timestamp: {interaction.get('timestamp')}")
                lines.append("")
            lines.append("The target made external connections to the Collaborator server.")
            lines.append("This confirms a blind vulnerability (SSRF, XXE, SQLi, etc.).")
        else:
            lines.append("[OK] No interactions detected within the poll window.")
            lines.append("The target did not make out-of-band connections (or they were delayed).")
            lines.append("Consider increasing poll_seconds or testing other parameters.")

        return "\n".join(lines)

    @mcp.tool()
    async def get_collaborator_interactions() -> str:
        """Check for Collaborator interactions (DNS, HTTP, SMTP). Presence confirms blind vulnerabilities. Requires Burp Professional."""
        data = await client.get("/api/collaborator/interactions")
        if "error" in data:
            return f"Error: {data['error']}"

        interactions = data.get("interactions", [])
        total = data.get("total", 0)

        if not interactions:
            return "No collaborator interactions detected yet. The target may not have triggered the payload."

        lines = [f"Collaborator Interactions ({total} total):\n"]
        for interaction in interactions:
            itype = interaction.get('type', '?')
            lines.append(f"  [{itype}] from {interaction.get('client_ip')}")
            lines.append(f"    Timestamp: {interaction.get('timestamp')}")
            lines.append(f"    Payload ID: {interaction.get('payload_id')}")

            # HTTP callback details (blind SSRF/XXE evidence)
            http = interaction.get("http_details", {})
            if http:
                lines.append(f"    HTTP: {http.get('method', '?')} {http.get('path', '/')}")
                body = http.get("request_body", "")
                if body:
                    lines.append(f"    Body: {body[:200]}")

            # DNS exfiltration details
            dns = interaction.get("dns_details", {})
            if dns:
                lines.append(f"    DNS: {dns.get('query_type', '?')} — {dns.get('description', '')}")

            lines.append("")

        return "\n".join(lines)
