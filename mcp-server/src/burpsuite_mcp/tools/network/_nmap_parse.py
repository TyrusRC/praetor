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
