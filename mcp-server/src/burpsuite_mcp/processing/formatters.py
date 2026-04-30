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
    """Format scanner findings grouped by severity with noise filtering and dedup."""
    items = data.get("items", [])
    total = data.get("total_findings", 0)

    if not items:
        return "No scanner findings. Run an active/passive scan in Burp first."

    # ── Noise filter: issues that waste Claude's context ──
    # These are informational-only and not actionable without chaining.
    _NOISE_NAMES = {
        "Strict transport security not enforced",
        "Content type incorrectly stated",
        "Input returned in response (reflected)",
        "Cacheable HTTPS response",
        "TLS certificate",
        "Cookie without HttpOnly flag set",
        "Cookie without Secure flag set",
        "Cookie scoped to parent domain",
        "Cross-domain Referer leakage",
        "HTTP TRACE method is enabled",
        "Long redirection response",
        "Backup file",
    }

    # ── Dedup: group same issue type + same host ──
    seen: dict[str, dict] = {}  # key: "name|host" -> {item, count, urls}
    noise_count = 0

    for item in items:
        name = item.get("name", "Unknown")
        sev = item.get("severity", "INFORMATION").upper()
        conf = item.get("confidence", "").upper()

        # Skip noise: INFORMATION + TENTATIVE is almost always false positive
        if sev == "INFORMATION" and conf == "TENTATIVE":
            noise_count += 1
            continue

        # Skip known noise by name
        if any(noise.lower() in name.lower() for noise in _NOISE_NAMES):
            noise_count += 1
            continue

        # Dedup key: issue name + host
        base_url = item.get("base_url", "")
        try:
            from urllib.parse import urlparse
            host = urlparse(base_url).netloc
        except Exception:
            host = base_url
        key = f"{name}|{host}"

        if key in seen:
            seen[key]["count"] += 1
            seen[key]["urls"].add(base_url)
        else:
            seen[key] = {"item": item, "count": 1, "urls": {base_url}}

    # Group deduped findings by severity
    by_severity: dict[str, list] = {}
    for entry in seen.values():
        sev = entry["item"].get("severity", "UNKNOWN").upper()
        by_severity.setdefault(sev, []).append(entry)

    actionable = sum(len(v) for v in by_severity.values())
    lines = [f"Scanner Findings ({actionable} actionable, {noise_count} noise filtered, {total} raw total):\n"]

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"]:
        findings = by_severity.get(severity, [])
        if not findings:
            continue
        # Sort by confidence: CERTAIN > FIRM > TENTATIVE
        conf_order = {"CERTAIN": 0, "FIRM": 1, "TENTATIVE": 2}
        findings.sort(key=lambda e: conf_order.get(e["item"].get("confidence", "").upper(), 3))

        lines.append(f"--- {severity} ({len(findings)}) ---")
        for entry in findings:
            f = entry["item"]
            count = entry["count"]
            conf = f.get("confidence", "?")
            name = f.get("name", "Unknown")

            count_str = f" (x{count})" if count > 1 else ""
            lines.append(f"  [{conf}] {name}{count_str}")
            lines.append(f"    URL: {f.get('base_url', 'N/A')}")

            # Show additional affected URLs if deduped
            if count > 1:
                extra_urls = list(entry["urls"] - {f.get("base_url", "")})
                for url in extra_urls[:3]:
                    lines.append(f"    Also: {url}")
                if len(extra_urls) > 3:
                    lines.append(f"    ...and {len(extra_urls) - 3} more URLs")

            if f.get("detail"):
                import re
                detail = re.sub(r'<[^>]+>', '', f["detail"])[:300].replace("\n", " ").strip()
                if detail:
                    lines.append(f"    Detail: {detail}")
            evidence = f.get("evidence", [])
            if evidence:
                ev = evidence[0]
                lines.append(f"    Evidence: {ev.get('method', '')} {ev.get('url', '')} -> {ev.get('status_code', '')}")
            lines.append("")

    if noise_count:
        lines.append(f"[{noise_count} informational/noise findings filtered — use get_scanner_findings(severity='INFORMATION') to see all]")

    return "\n".join(lines)
