"""Output formatting helpers shared by the testing tools."""


def fmt_size(n: int) -> str:
    """Format byte size compactly (e.g. 1024 -> '1.0K')."""
    if n < 1024:
        return f"{n}B"
    return f"{n/1024:.1f}K"


def format_fuzz_results(data: dict) -> str:
    """Format fuzz results into a compact, analysis-friendly table."""
    results = data.get("results", [])
    total = data.get("total_requests", 0)
    baseline_status = data.get("baseline_status", "?")
    baseline_length = data.get("baseline_length", "?")

    lines = [f"Fuzz Results ({total} requests, baseline: {baseline_status}/{baseline_length} bytes):\n"]

    # Table header
    header = f"{'#':<4} {'PARAM':<15} {'PAYLOAD':<35} {'STATUS':<8} {'LENGTH':<10} {'TIME':<8}"
    grep_keys = set()
    for r in results:
        grep_keys.update(r.get("grep_matches", {}).keys())
    if grep_keys:
        header += " " + " ".join(f"{k[:8]:<8}" for k in sorted(grep_keys))
    header += " FLAGS"
    lines.append(header)
    lines.append("-" * len(header))

    for r in results:
        payload_display = r.get("payload", "")[:33]
        if len(r.get("payload", "")) > 33:
            payload_display += ".."

        anomalies = r.get("anomalies", [])
        flags = " ".join(f"[!{a}]" for a in anomalies) if anomalies else ""

        line = (
            f"{r.get('payload_index', '?'):<4} "
            f"{r.get('parameter', '?'):<15} "
            f"{payload_display:<35} "
            f"{r.get('status_code', '?'):<8} "
            f"{r.get('response_length', '?'):<10} "
            f"{r.get('response_time_ms', '?'):<8}"
        )

        # Grep matches
        grep = r.get("grep_matches", {})
        if grep_keys:
            line += " " + " ".join(f"{grep.get(k, 0):<8}" for k in sorted(grep_keys))

        line += f" {flags}"
        lines.append(line)

        # Show response snippet for anomalous results
        snippet = r.get("response_snippet", "")
        if snippet and anomalies:
            lines.append(f"     > {snippet[:120]}")

    # Anomaly summary
    summary = data.get("anomaly_summary", {})
    if summary:
        lines.append(f"\n--- Anomaly Summary ---")
        if summary.get("status_anomalies"):
            lines.append(f"  [!STATUS] {summary['status_anomalies']} responses with different status code")
        if summary.get("length_anomalies"):
            lines.append(f"  [!LENGTH] {summary['length_anomalies']} responses with unusual length")
        if summary.get("timing_anomalies"):
            lines.append(f"  [!TIMING] {summary['timing_anomalies']} responses with unusual timing")
        if summary.get("grep_hits"):
            lines.append(f"  [!GREP]   {summary['grep_hits']} grep pattern matches")

    return "\n".join(lines)
