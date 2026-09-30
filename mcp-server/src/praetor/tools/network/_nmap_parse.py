"""Parse nmap XML into a normalised host/service inventory.

Pure stdlib (xml.etree) so it is testable against a fixture without running a
scan. Returns:

    {
      "hosts": [
        {"ip": "1.2.3.4", "hostnames": ["web01"], "ports": [
            {"port": 443, "proto": "tcp", "state": "open",
             "service": "http", "product": "nginx", "version": "1.18",
             "tunnel": "ssl"},
        ]},
      ],
    }

Only hosts that are up and ports whose state is `open` (or `open|filtered`)
are kept — closed/filtered noise is dropped.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

# Service names (or nmap service guesses) that mean "there is a web server here".
HTTP_SERVICES = {"http", "https", "http-alt", "https-alt", "http-proxy", "https", "sip", "soap"}
# Ports that are web servers often enough to bridge even when the service name
# is unknown (e.g. -sS without -sV).
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000, 8081, 9000, 9443}


def parse_nmap_xml(xml_text: str) -> dict:
    """Parse nmap -oX output. Raises ValueError on malformed XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"malformed nmap XML: {e}") from e

    hosts: list[dict] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            # MAC-only host (link-local) — skip; nothing to scan over IP.
            continue

        hostnames = [
            hn.get("name", "")
            for hn in host.findall("hostnames/hostname")
            if hn.get("name")
        ]

        ports: list[dict] = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if not state.startswith("open"):
                continue
            svc = port.find("service")
            ports.append({
                "port": int(port.get("portid", "0") or 0),
                "proto": port.get("protocol", "tcp"),
                "state": state,
                "service": (svc.get("name", "") if svc is not None else ""),
                "product": (svc.get("product", "") if svc is not None else ""),
                "version": (svc.get("version", "") if svc is not None else ""),
                "tunnel": (svc.get("tunnel", "") if svc is not None else ""),
            })

        hosts.append({"ip": ip, "hostnames": hostnames, "ports": ports})

    return {"hosts": hosts}


# ---------------------------------------------------------------------------
# Interpretation — nmap output is INFERENCE from probe responses, not ground
# truth. parse_nmap_xml() keeps only `open` ports for the inventory; the
# interpretation below reads ALL port states (filtered/unfiltered/closed/
# open|filtered) because that is where an ACK/FIN/NULL/XMAS/UDP scan's meaning
# lives, and turns them into the human-readable notes a verdict needs.
# ---------------------------------------------------------------------------

# One-line reminder carried in every scan result (full version in the skill).
KEY_PRINCIPLE = (
    "nmap output is INFERENCE from probe responses, not ground truth — "
    "corroborate a surprising verdict with packet-level observation (Wireshark, "
    "or Praetor's tcp_proxy_* TCP capture) before trusting it."
)


def _state_tally(root: ET.Element) -> dict[str, int]:
    """Count port states across all hosts (all states, not just open)."""
    tally: dict[str, int] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        for port in host.findall("ports/port"):
            st = port.find("state")
            s = st.get("state", "") if st is not None else ""
            if s:
                tally[s] = tally.get(s, 0) + 1
    return tally


def interpret_scan(xml_text: str, scan_type: str) -> list[str]:
    """Human-readable interpretation notes for a given scan_type.

    Best-effort and advisory: never raises. Returns [] when the scan_type has
    no special interpretation (syn/connect read open/closed directly) or the
    XML is unparseable.
    """
    st = (scan_type or "").strip().lower()
    if st in ("", "syn", "connect"):
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    tally = _state_tally(root)
    notes: list[str] = []

    if st == "ack":
        unfiltered = tally.get("unfiltered", 0)
        filtered = tally.get("filtered", 0)
        notes.append(
            "ACK scan maps FIREWALL filtering, not open/closed: it cannot tell "
            "you which ports are open."
        )
        notes.append(
            f"  {unfiltered} unfiltered (ACK got an RST back -> no stateful "
            f"firewall dropping this port), {filtered} filtered (no response / "
            "ICMP unreachable -> a stateful firewall is dropping the ACK)."
        )
        if unfiltered and not filtered:
            notes.append("  All-unfiltered -> no stateful packet filter in the path "
                         "(or it fails open). Follow up with -sS to find open ports.")
        elif filtered and not unfiltered:
            notes.append("  All-filtered -> a stateful firewall is in the path. "
                         "Try FIN/NULL/XMAS (-sF/-sN/-sX) to slip past it.")

    elif st in ("fin", "null", "xmas"):
        openfilt = tally.get("open|filtered", 0)
        closed = tally.get("closed", 0)
        filtered = tally.get("filtered", 0)
        notes.append(
            f"{st.upper()} scan (stateless-firewall bypass + OS inference): "
            "RFC 793 stacks reply RST to a closed port and DROP on open|filtered."
        )
        notes.append(
            f"  {openfilt} open|filtered (no RST -> port may be open, RFC-compliant "
            f"stack), {closed} closed (RST received), {filtered} filtered."
        )
        if closed and not openfilt:
            notes.append(
                "  OS INFERENCE: every probed port replied RST (all 'closed'), never "
                "silent -> a NON-RFC-793 stack that RSTs regardless of state. Likely "
                "Windows / Cisco IOS / BSD-derived device, and this scan type cannot "
                "distinguish open from closed here. Confirm with -sS + -O."
            )
        elif openfilt:
            notes.append(
                "  OS INFERENCE: some ports went silent (open|filtered) -> an "
                "RFC-793-compliant stack (typical Linux/Unix). The open|filtered set "
                "is your open-port candidate list; confirm each with -sS."
            )

    elif st == "udp":
        openp = tally.get("open", 0)
        openfilt = tally.get("open|filtered", 0)
        closed = tally.get("closed", 0)
        notes.append(
            "UDP scan is connectionless: 'open|filtered' means NO reply was seen "
            "(the service may be open and silent, OR a firewall dropped the probe) "
            "-- it is NOT a confirmed-open verdict."
        )
        notes.append(
            f"  {openp} open (a UDP payload came back), {openfilt} open|filtered "
            f"(no response), {closed} closed (ICMP port-unreachable received)."
        )
        notes.append(
            "  UDP is slow (ICMP-unreachable rate limiting) -- pair with --top-ports "
            "and a service-specific NSE script to disambiguate open|filtered."
        )

    return notes


def is_http_service(port: dict) -> bool:
    """True if a parsed port entry looks like a web server."""
    svc = (port.get("service") or "").lower()
    if svc in HTTP_SERVICES or svc.startswith("http"):
        return True
    if port.get("tunnel") == "ssl" and port.get("proto") == "tcp":
        return True
    return port.get("proto") == "tcp" and port.get("port") in HTTP_PORTS


def http_targets(inventory: dict) -> list[str]:
    """Bridge to the web lane: URLs for every HTTP(S) service in the inventory.

    Prefers a hostname over the bare IP (vhost-correct), and https when the
    port is TLS-tunnelled or a well-known TLS port.
    """
    urls: list[str] = []
    tls_ports = {443, 8443, 9443}
    for host in inventory.get("hosts", []):
        name = host["hostnames"][0] if host.get("hostnames") else host.get("ip", "")
        if not name:
            continue
        for port in host.get("ports", []):
            if not is_http_service(port):
                continue
            p = port.get("port", 0)
            tls = port.get("tunnel") == "ssl" or p in tls_ports or \
                (port.get("service") or "").lower() in ("https", "https-alt")
            scheme = "https" if tls else "http"
            default = (scheme == "https" and p == 443) or (scheme == "http" and p == 80)
            urls.append(f"{scheme}://{name}" if default else f"{scheme}://{name}:{p}")
    # Stable, de-duplicated.
    return sorted(set(urls))
