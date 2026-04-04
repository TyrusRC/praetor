"""Format Burp data into compact, token-efficient representations for the LLM."""


def format_proxy_table(data: dict) -> str:
    """Format proxy history as a compact ASCII table."""
    items = data.get("items", [])
    total = data.get("total", 0)
    offset = data.get("offset", 0)

    if not items:
        return "Proxy history is empty. Browse targets through Burp's proxy first."

    lines = [f"Proxy History ({total} total, showing {offset}-{offset + len(items)}):\n"]
    lines.append(f"{'INDEX':<8} {'METHOD':<8} {'STATUS':<8} {'SIZE':<8} {'MIME':<15} URL")
    lines.append("-" * 100)

    for item in items:
        lines.append(
            f"{item['index']:<8} "
            f"{item['method']:<8} "
            f"{item.get('status_code', '-'):<8} "
            f"{item.get('response_length', 0):<8} "
            f"{item.get('mime_type', ''):<15} "
            f"{item['url']}"
        )

    return "\n".join(lines)


def format_findings(data: dict) -> str:
    """Format scanner findings grouped by severity."""
    items = data.get("items", [])
    total = data.get("total_findings", 0)

    if not items:
        return "No scanner findings. Run an active/passive scan in Burp first."

    # Group by severity
    by_severity: dict[str, list] = {}
    for item in items:
        sev = item.get("severity", "UNKNOWN")
        by_severity.setdefault(sev, []).append(item)

    lines = [f"Scanner Findings ({total} total, {len(items)} returned):\n"]

    for severity in ["HIGH", "MEDIUM", "LOW", "INFORMATION"]:
        findings = by_severity.get(severity, [])
        if not findings:
            continue
        lines.append(f"--- {severity} ({len(findings)}) ---")
        for f in findings:
            lines.append(f"  [{f.get('confidence', '?')}] {f.get('name')}")
            lines.append(f"    URL: {f.get('base_url', 'N/A')}")
            if f.get("detail"):
                detail = f["detail"][:300].replace("\n", " ")
                lines.append(f"    Detail: {detail}")
            evidence = f.get("evidence", [])
            if evidence:
                ev = evidence[0]
                lines.append(f"    Evidence: {ev.get('method', '')} {ev.get('url', '')} -> {ev.get('status_code', '')}")
            lines.append("")

    return "\n".join(lines)
