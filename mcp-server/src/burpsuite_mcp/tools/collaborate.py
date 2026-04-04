"""Tools for Burp Collaborator - out-of-band testing for blind vulnerabilities."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_collaborator_payload() -> str:
        """Generate a Burp Collaborator payload URL for out-of-band (OOB) testing.
        Use for detecting blind SSRF, blind XXE, blind SQL injection, blind XSS, etc.
        Inject the payload URL into parameters and then check for interactions.
        Requires Burp Suite Professional."""
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
    async def auto_collaborator_test(
        index: int,
        parameter: str,
        injection_point: str = "query",
        poll_seconds: int = 5,
    ) -> str:
        """Automated Burp Collaborator test - inject payload, send request, and poll for interactions.
        One-step out-of-band vulnerability detection: generates a Collaborator payload,
        injects it into the specified parameter, sends the request, waits, and checks for interactions.

        If interactions are detected, the target is making out-of-band connections = VULNERABLE.
        Use for: blind SSRF, blind XXE, blind SQL injection, blind command injection, etc.
        Requires Burp Suite Professional.

        Args:
            index: Proxy history index of the request to test
            parameter: Parameter name to inject the payload into
            injection_point: Where to inject - 'query', 'body', or 'header' (default: query)
            poll_seconds: Seconds to wait before polling for interactions (default: 5, max: 15)
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
        """Check for Burp Collaborator interactions (DNS, HTTP, SMTP lookups).
        Call this after injecting a collaborator payload to see if the target made
        an out-of-band connection. Presence of interactions confirms blind vulnerabilities.
        Requires Burp Suite Professional."""
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
