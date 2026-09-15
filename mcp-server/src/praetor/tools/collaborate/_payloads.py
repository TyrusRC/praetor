"""Collaborator payloads: single, pool, status, interactions."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from ._oast import _COLLAB_POOL, _pool_lock


def _filter_interactions(interactions: list[dict], type_filter: str) -> list[dict]:
    """Keep only interactions whose type matches ``type_filter`` (case-insensitive
    exact match on the interaction's ``type`` field, e.g. HTTP/DNS/SMTP).

    An empty/blank filter returns the list unchanged. Used to cut through DNS
    resolver noise on OOB-exfil labs (cookie theft, blind XXE/SSRF) where the
    payload data lands in the HTTP/SMTP body and the DNS lookups are chaff.
    """
    if not type_filter or not type_filter.strip():
        return interactions
    want = type_filter.strip().upper()
    return [i for i in interactions if str(i.get("type", "")).upper() == want]


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
        # Fan out the allocations concurrently. Burp's Collaborator endpoint
        # is per-request idempotent and the extension's 24-thread pool absorbs
        # the burst easily; sequential allocation was the prior bottleneck
        # (25 calls × ~100ms ≈ 2.5s). asyncio.gather collapses to one batch.
        import asyncio as _asyncio
        results = await _asyncio.gather(
            *(client.post("/api/collaborator/payload") for _ in range(count)),
            return_exceptions=True,
        )
        added = 0
        errors = 0
        new_entries: list[dict] = []
        for data in results:
            if isinstance(data, Exception) or (isinstance(data, dict) and "error" in data):
                errors += 1
                # Burp Pro likely missing — bail early on a clear failure run
                # to avoid burning the whole batch on a pre-broken endpoint.
                if errors >= 3 and added == 0:
                    break
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
    async def get_collaborator_interactions(type_filter: str = "") -> str:
        """Check for Collaborator interactions (DNS, HTTP, SMTP). Presence confirms blind vulnerabilities. Requires Burp Professional.

        Args:
            type_filter: Show only interactions of this type (HTTP/DNS/SMTP,
                case-insensitive). Default "" shows all. Pass "HTTP" on
                OOB-exfil labs (cookie theft, blind XXE/SSRF) to skip the
                DNS resolver chaff and see just the callback bodies that
                carry the exfiltrated data.
        """
        data = await client.get("/api/collaborator/interactions")
        if "error" in data:
            return f"Error: {data['error']}"

        total = data.get("total", 0)
        interactions = _filter_interactions(data.get("interactions", []), type_filter)

        if not interactions:
            if type_filter and total:
                return (f"No {type_filter.strip().upper()} collaborator interactions "
                        f"(of {total} total across all types). Retry without type_filter "
                        f"to see other channels.")
            return "No collaborator interactions detected yet. The target may not have triggered the payload."

        # Interactions are retained server-side across polls; new_in_poll counts
        # only those drained on this call.
        new_in_poll = data.get("new_in_poll")
        header = f"Collaborator Interactions ({total} total"
        if new_in_poll is not None:
            header += f", {new_in_poll} new this poll"
        if type_filter and type_filter.strip():
            header += f", {len(interactions)} {type_filter.strip().upper()}"
        header += "):\n"
        lines = [header]
        for interaction in interactions:
            itype = interaction.get('type', '?')
            lines.append(f"  [{itype}] from {interaction.get('client_ip')}")
            lines.append(f"    Timestamp: {interaction.get('timestamp')}")
            lines.append(f"    Payload ID: {interaction.get('payload_id')}")

            # HTTP callback details (blind SSRF/XXE evidence)
            http = interaction.get("http_details", {})
            if http:
                lines.append(f"    HTTP: {http.get('method', '?')} {http.get('path', '/')}")
                # Host header carries subdomain-exfiltrated data (<data>.<id>...).
                if http.get("host"):
                    lines.append(f"    Host: {http['host']}")
                body = http.get("request_body", "")
                if body:
                    lines.append(f"    Body: {body[:200]}")

            # DNS exfiltration details
            dns = interaction.get("dns_details", {})
            if dns:
                lines.append(f"    DNS: {dns.get('query_type', '?')} — {dns.get('description', '')}")
                # The queried name is where DNS-channel exfil data lands.
                if dns.get("query_name"):
                    lines.append(f"    Query: {dns['query_name']}")

            lines.append("")

        return "\n".join(lines)
