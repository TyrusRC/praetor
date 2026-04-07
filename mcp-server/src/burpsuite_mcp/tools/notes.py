"""Tools for saving findings and generating reports."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def save_finding(
        title: str,
        description: str,
        severity: str = "INFO",
        endpoint: str = "",
        evidence: str = "",
        status: str = "suspected",
    ) -> str:
        """Save a pentest finding/vulnerability note.
        Use this to document discovered vulnerabilities during testing.

        Args:
            title: Short finding title (e.g. "SQL Injection in login form")
            description: Detailed description of the vulnerability
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            endpoint: Affected URL/endpoint
            evidence: Proof (request/response snippets, payloads used)
            status: Finding status — 'suspected', 'confirmed', 'stale', or 'likely_false_positive'
        """
        data = await client.post("/api/notes/findings", json={
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "evidence": evidence,
            "status": status,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        return f"Finding saved: [{data.get('severity')}] {data.get('title')} (ID: {data.get('id')})"

    @mcp.tool()
    async def get_findings(endpoint: str = "") -> str:
        """Get all saved pentest findings, optionally filtered by endpoint URL."""
        params = {}
        if endpoint:
            params["endpoint"] = endpoint

        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        findings = data.get("findings", [])
        if not findings:
            return "No findings saved yet."

        lines = [f"Saved Findings ({data.get('total', 0)}):\n"]
        for f in findings:
            lines.append(f"[{f.get('severity')}] #{f.get('id')} - {f.get('title')}")
            if f.get("endpoint"):
                lines.append(f"  Endpoint: {f['endpoint']}")
            if f.get("description"):
                lines.append(f"  {f['description'][:200]}")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def export_report(format: str = "markdown") -> str:
        """Export all findings as a pentest report.

        Args:
            format: 'markdown' or 'json'
        """
        data = await client.get("/api/notes/export", params={"format": format})
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "json":
            return str(data)
        return data.get("content", "No findings to export.")
