"""Scanner control + issue dashboard — manage scans and view findings by severity."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def cancel_scan(scan_id: int) -> str:
        """Cancel an active scan by its ID.

        Args:
            scan_id: Numeric scan ID returned when the scan was started
        """
        data = await client.delete(f"/api/scanner/scan/{scan_id}")
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Scan {scan_id} cancelled.")

    @mcp.tool()
    async def get_issues_dashboard() -> str:
        """Compact dashboard of all Burp scanner findings grouped by severity with affected hosts and top issues."""
        data = await client.get("/api/scanner/findings", params={"limit": 500})
        if "error" in data:
            return f"Error: {data['error']}"

        items = data.get("items", [])
        total = data.get("total_findings", len(items))

        if not items:
            return "No scanner findings. Run a scan or browse the target through Burp first."

        # Count by severity
        by_severity: dict[str, list] = {}
        hosts: set[str] = set()
        for item in items:
            sev = item.get("severity", "INFORMATION").upper()
            by_severity.setdefault(sev, []).append(item)
            url = item.get("base_url", "")
            if url:
                try:
                    from urllib.parse import urlparse
                    hosts.add(urlparse(url).netloc)
                except Exception:
                    pass

        lines = [f"Burp Scanner Dashboard ({total} findings)", "=" * 50, ""]

        # Severity summary
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"]:
            count = len(by_severity.get(sev, []))
            if count:
                bar = "#" * min(count, 30)
                lines.append(f"  {sev:<12} {count:>4}  {bar}")
        lines.append("")

        # Affected hosts
        if hosts:
            lines.append(f"Affected hosts ({len(hosts)}):")
            for h in sorted(hosts):
                lines.append(f"  {h}")
            lines.append("")

        # Top critical/high findings (most actionable)
        for sev in ["CRITICAL", "HIGH"]:
            findings = by_severity.get(sev, [])
            if findings:
                lines.append(f"--- {sev} ({len(findings)}) ---")
                seen_names: set[str] = set()
                for f in findings:
                    name = f.get("name", "Unknown")
                    if name in seen_names:
                        continue
                    seen_names.add(name)
                    conf = f.get("confidence", "")
                    url = f.get("base_url", "")
                    lines.append(f"  [{conf}] {name}")
                    if url:
                        lines.append(f"    {url}")
                    detail = f.get("detail", "")
                    if detail:
                        # Strip HTML tags for clean output
                        import re
                        clean = re.sub(r'<[^>]+>', '', detail)[:150]
                        lines.append(f"    {clean}")
                lines.append("")

        # Medium findings (summarized)
        medium = by_severity.get("MEDIUM", [])
        if medium:
            lines.append(f"--- MEDIUM ({len(medium)}) ---")
            med_names: dict[str, int] = {}
            for f in medium:
                name = f.get("name", "Unknown")
                med_names[name] = med_names.get(name, 0) + 1
            for name, count in sorted(med_names.items(), key=lambda x: -x[1]):
                lines.append(f"  {name} (x{count})" if count > 1 else f"  {name}")
            lines.append("")

        # Next steps
        lines.append("Next steps:")
        crit_high = len(by_severity.get("CRITICAL", [])) + len(by_severity.get("HIGH", []))
        if crit_high:
            lines.append(f"  1. Investigate {crit_high} critical/high findings with get_scanner_findings(severity='HIGH')")
            lines.append(f"  2. Verify each with assess_finding() before reporting")
        if medium:
            lines.append(f"  3. Review {len(medium)} medium findings for exploitability")
        lines.append(f"  4. Poll for new findings: get_new_findings(since_count={total})")

        return "\n".join(lines)

    @mcp.tool()
    async def get_new_findings(since_count: int = 0) -> str:
        """Get scanner findings added since a specific count for incremental polling during active scans.

        Args:
            since_count: Number of findings already seen; only newer ones are returned
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
