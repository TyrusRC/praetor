"""Implementation for probe_race_singlepacket / probe_race_http3_datagram —
split from race_singlepacket.py to keep the tool wrappers thin. The wrappers in
race_singlepacket.py own the @mcp.tool() signatures + docstrings and delegate
here."""

from urllib.parse import urlparse

from praetor import client
from praetor.tools.testing._verdict import error_verdict, make_verdict

from ._race_helpers import (
    _singlepacket_exchange,
    _tally_race,
    _detect_h3_advertised,
)


async def _run_probe_race_singlepacket(
    target_url: str,
    method: str = "POST",
    body: str = "",
    headers: dict | None = None,
    concurrent: int = 20,
    expect_once: bool = True,
) -> dict:
    if concurrent < 2:
        return error_verdict("concurrent must be >= 2", vuln_type="race_condition")
    concurrent = min(concurrent, 100)

    # Scope check
    scope = await client.check_scope(target_url)
    if "error" in scope:
        return error_verdict(f"scope check failed: {scope['error']}", vuln_type="race_condition")
    if not scope.get("in_scope", False):
        return error_verdict(f"{target_url} not in scope", vuln_type="race_condition")

    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return error_verdict(
            "HTTP/2 single-packet requires HTTPS; use probe_race_lastbyte for HTTP",
            vuln_type="race_condition",
        )
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Build N identical requests (same as Turbo Intruder use case)
    request_template = {
        "method": method,
        "path": path,
        "headers": dict(headers or {}),
        "body": body,
    }
    requests = [dict(request_template) for _ in range(concurrent)]

    # Coalesce N stream frames into one TCP packet through Burp (h2 transport).
    try:
        results, buf, stream_ids, flush_ns = await _singlepacket_exchange(
            host, port, requests, read_timeout=15.0
        )
    except Exception as e:
        return error_verdict(
            f"H2 single-packet exchange failed via Burp: {type(e).__name__}: {e}",
            vuln_type="race_condition",
        )

    # Analyse
    lines = [
        f"probe_race_singlepacket {method} {target_url}",
        f"H2 streams: {concurrent} | flush window: {flush_ns / 1_000_000:.3f} ms (single TCP packet)",
        f"Buffer size: {len(buf)} bytes",
        "",
    ]
    statuses, success_count, time_samples, stream_lines = _tally_race(stream_ids, results)
    lines.extend(stream_lines)

    lines.append("")
    lines.append(f"Status distribution: {dict(statuses)}")
    lines.append(f"Successful (2xx): {success_count}")
    if time_samples:
        t_min = min(time_samples) / 1_000_000
        t_max = max(time_samples) / 1_000_000
        t_avg = sum(time_samples) / len(time_samples) / 1_000_000
        lines.append(f"Response time range: {t_min:.2f} - {t_max:.2f} ms (avg {t_avg:.2f} ms, jitter {t_max - t_min:.2f} ms)")

    if expect_once and success_count > 1:
        lines.append(f"\n*** RACE CONFIRMED: {success_count} successes from {concurrent} single-packet streams ***")
        lines.append("Verify side effect in persistent state (DB rows, balance, transaction ledger).")
    elif success_count == 1:
        lines.append("\nSingle 2xx — race not observed at this concurrency.")
    elif success_count == 0:
        lines.append("\nNo 2xx responses — endpoint may not be reachable as configured; check status distribution.")

    human = "\n".join(lines)
    if expect_once and success_count > 1:
        verdict, confidence = "CONFIRMED", 0.9
        ev = f"H2 single-packet race confirmed: {success_count} successes from {concurrent} streams"
    elif success_count == 1:
        verdict, confidence = "FAILED", 0.1
        ev = "single 2xx — race not observed at this concurrency"
    else:
        verdict, confidence = "FAILED", 0.1
        ev = "no 2xx responses — endpoint may not be reachable as configured"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="race_condition",
        details={
            "target_url": target_url,
            "concurrent": concurrent,
            "success_count": success_count,
            "expect_once": expect_once,
        },
        summary=human,
    )


async def _run_probe_race_http3_datagram(
    target_url: str,
    method: str = "POST",
    body: str = "",
    headers: dict | None = None,
    concurrent: int = 100,
    expect_once: bool = True,
    require_h3_advertised: bool = True,
) -> dict:
    if concurrent < 2:
        return error_verdict("concurrent must be >= 2", vuln_type="race_condition")
    concurrent = min(concurrent, 100)

    scope = await client.check_scope(target_url)
    if "error" in scope:
        return error_verdict(f"scope check failed: {scope['error']}", vuln_type="race_condition")
    if not scope.get("in_scope", False):
        return error_verdict(f"{target_url} not in scope", vuln_type="race_condition")

    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return error_verdict(
            "HTTP/3 datagram race requires HTTPS (QUIC is TLS-only)",
            vuln_type="race_condition",
        )
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # (a) QUIC-listener precondition: Alt-Svc must advertise h3.
    h3_targets = await _detect_h3_advertised(target_url)
    if require_h3_advertised and not h3_targets:
        return make_verdict(
            "FAILED", 0.1,
            "no Alt-Svc h3 advertisement; origin exposes no QUIC/h3 listener",
            vuln_type="race_condition",
            details={"target_url": target_url, "h3_advertised": False},
            summary=(
                f"probe_race_http3_datagram {method} {target_url}\n"
                "No Alt-Svc h3=... advertisement -- origin exposes no QUIC listener.\n"
                "H3 single-datagram race not applicable. Re-run with "
                "require_h3_advertised=False to force."
            ),
        )

    # (b) Coalesced single-packet race over the Burp-observable H2 path.
    requests = [
        {"method": method, "path": path, "headers": dict(headers or {}), "body": body}
        for _ in range(concurrent)
    ]
    try:
        results, buf, stream_ids, flush_ns = await _singlepacket_exchange(
            host, port, requests, read_timeout=15.0
        )
    except Exception as e:
        return error_verdict(
            f"H3-datagram race exchange failed via Burp: {type(e).__name__}: {e}",
            vuln_type="race_condition",
        )

    statuses, success_count, time_samples, stream_lines = _tally_race(stream_ids, results)
    lines = [
        f"probe_race_http3_datagram {method} {target_url}",
        f"h3 advertised: {h3_targets or 'forced (require_h3_advertised=False)'}",
        f"coalesced requests: {concurrent} | flush window: {flush_ns / 1_000_000:.3f} ms (single packet)",
        "transport: Burp H2 downgrade path (QUIC datagram assembly = ceiling, see tool NOTE)",
        f"Buffer size: {len(buf)} bytes",
        "",
    ]
    lines.extend(stream_lines)
    lines.append("")
    lines.append(f"Status distribution: {dict(statuses)}")
    lines.append(f"Successful (2xx): {success_count}")
    if time_samples:
        t_min = min(time_samples) / 1_000_000
        t_max = max(time_samples) / 1_000_000
        t_avg = sum(time_samples) / len(time_samples) / 1_000_000
        lines.append(f"Response time range: {t_min:.2f} - {t_max:.2f} ms (avg {t_avg:.2f} ms, jitter {t_max - t_min:.2f} ms)")

    if expect_once and success_count > 1:
        lines.append(f"\n*** RACE CONFIRMED: {success_count} successes from {concurrent} coalesced requests ***")
        lines.append("Verify side effect in persistent state (DB rows, balance, ledger).")
        verdict, confidence = "CONFIRMED", 0.9
        ev = f"H3-gated single-packet race: {success_count} successes from {concurrent} coalesced requests"
    elif success_count == 1:
        lines.append("\nSingle 2xx -- race not observed at this concurrency.")
        verdict, confidence = "FAILED", 0.1
        ev = "single 2xx -- race not observed at this concurrency"
    else:
        lines.append("\nNo 2xx responses -- endpoint may not be reachable as configured; check status distribution.")
        verdict, confidence = "FAILED", 0.1
        ev = "no 2xx responses -- endpoint may not be reachable as configured"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="race_condition",
        details={
            "target_url": target_url,
            "concurrent": concurrent,
            "success_count": success_count,
            "expect_once": expect_once,
            "h3_advertised": h3_targets,
            "transport_note": "ran over Burp H2 downgrade path; true QUIC single-datagram assembly is the ceiling",
        },
        summary="\n".join(lines),
    )
