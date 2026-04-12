"""Additional scanner control tools — pause, resume, cancel scans and poll for new findings."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def cancel_scan(scan_id: int) -> str:
        """Cancel an active scan by its ID. The scan will be stopped and removed from the
        active scans list. Use get_scan_status() to find scan IDs of running scans.

        Args:
            scan_id: The numeric scan ID returned when the scan was started
        """
        data = await client.delete(f"/api/scanner/scan/{scan_id}")
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Scan {scan_id} cancelled.")

    @mcp.tool()
    async def pause_scan(scan_id: int) -> str:
        """Get status of an active scan. Note: Burp Montoya API does not support pausing scans.
        Returns current scan status instead.

        Args:
            scan_id: The numeric scan ID to check
        """
        data = await client.post(f"/api/scanner/scan/{scan_id}/pause")
        if "error" in data:
            return f"Error: {data['error']}"
        msg = data.get("message", "")
        status = data.get("status", "")
        lines = [msg] if msg else []
        if status:
            lines.append(f"Status: {status}")
        if data.get("request_count"):
            lines.append(f"Requests: {data['request_count']}, Issues: {data.get('issue_count', 0)}")
        return "\n".join(lines) if lines else f"Scan {scan_id} status retrieved."

    @mcp.tool()
    async def resume_scan(scan_id: int) -> str:
        """Get status of an active scan. Note: Burp Montoya API does not support resume — scans run continuously.
        Returns current scan status.

        Args:
            scan_id: The numeric scan ID to check
        """
        data = await client.post(f"/api/scanner/scan/{scan_id}/resume")
        if "error" in data:
            return f"Error: {data['error']}"
        msg = data.get("message", "")
        status = data.get("status", "")
        lines = [msg] if msg else []
        if status:
            lines.append(f"Status: {status}")
        if data.get("request_count"):
            lines.append(f"Requests: {data['request_count']}, Issues: {data.get('issue_count', 0)}")
        return "\n".join(lines) if lines else f"Scan {scan_id} status retrieved."

    @mcp.tool()
    async def get_new_findings(since_count: int = 0) -> str:
        """Get scanner findings added since a specific count. Useful for polling to detect
        new findings in real-time during an active scan.

        Workflow:
        1. Call get_new_findings(since_count=0) to get current total and baseline findings
        2. After some time, call get_new_findings(since_count=<previous_total>) to get only new ones
        3. Repeat step 2 to keep polling for new findings

        This avoids re-fetching already-seen findings and is more efficient than
        calling get_scanner_findings() repeatedly.

        Args:
            since_count: Number of findings already seen. Findings after this count are returned.
                         Use 0 to get all current findings and the total count.
        """
        data = await client.get("/api/scanner/findings/new", params={"since": since_count})
        if "error" in data:
            return f"Error: {data['error']}"

        total = data.get("total", 0)
        findings = data.get("items", [])

        if not findings:
            return f"No new findings since count {since_count}. Total findings: {total}"

        lines = [f"New findings since #{since_count} ({len(findings)} new, {total} total):\n"]
        for f in findings:
            severity = f.get("severity", "unknown")
            name = f.get("name", "Unknown")
            url = f.get("base_url", "")
            confidence = f.get("confidence", "")
            lines.append(f"  [{severity.upper()}] {name}")
            if url:
                lines.append(f"    URL: {url}")
            if confidence:
                lines.append(f"    Confidence: {confidence}")

        lines.append(f"\nTotal findings: {total}")
        lines.append(f"Poll next with: get_new_findings(since_count={total})")
        return "\n".join(lines)
