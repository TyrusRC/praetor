"""rdap_lookup — keyless WHOIS-equivalent via RDAP (RFC 9082/9083).

RDAP is the structured JSON successor to WHOIS. rdap.org bootstraps to the
authoritative registry for any domain or IP, no API key, no scraping. Fills
the WHOIS gap (registrar, registrant org, dates, nameservers, network owner).
"""

import ipaddress

import httpx
from mcp.server.fastmcp import FastMCP

from ._common import _sanitize_domain


def _is_ip(query: str) -> bool:
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False


def _events(data: dict) -> dict:
    """Flatten RDAP events → {action: date}."""
    out: dict[str, str] = {}
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date:
            out[action] = date
    return out


def _entities(data: dict) -> list[str]:
    """Extract 'role: name/org' lines from RDAP entities (recurses one level)."""
    lines: list[str] = []

    def _one(ent: dict) -> None:
        roles = ", ".join(ent.get("roles", []) or []) or "?"
        name = ent.get("handle", "")
        # vcardArray carries fn/org as ["fn", {}, "text", "<value>"] triples.
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
                    name = str(item[3]) or name
                    break
        lines.append(f"  [{roles}] {name}".rstrip())

    for ent in data.get("entities", []) or []:
        _one(ent)
        for sub in ent.get("entities", []) or []:
            _one(sub)
    return lines


def _format_domain(data: dict) -> str:
    lines = [f"RDAP domain: {data.get('ldhName', data.get('handle', '?'))}"]
    status = ", ".join(data.get("status", []) or [])
    if status:
        lines.append(f"Status: {status}")
    ev = _events(data)
    for label, key in (("Registered", "registration"), ("Last changed", "last changed"),
                       ("Expires", "expiration")):
        if key in ev:
            lines.append(f"{label}: {ev[key]}")
    ns = [n.get("ldhName", "") for n in data.get("nameservers", []) or []]
    ns = [n for n in ns if n]
    if ns:
        lines.append("Nameservers: " + ", ".join(sorted(ns)))
    if data.get("secureDNS", {}).get("delegationSigned"):
        lines.append("DNSSEC: signed")
    ents = _entities(data)
    if ents:
        lines.append("Contacts:")
        lines.extend(ents)
    return "\n".join(lines)


def _format_ip(data: dict) -> str:
    lines = [f"RDAP network: {data.get('handle', '?')}"]
    name = data.get("name")
    if name:
        lines.append(f"Name: {name}")
    rng = f"{data.get('startAddress', '?')} - {data.get('endAddress', '?')}"
    lines.append(f"Range: {rng}")
    for key, label in (("type", "Type"), ("country", "Country"), ("ipVersion", "IP version")):
        if data.get(key):
            lines.append(f"{label}: {data[key]}")
    ents = _entities(data)
    if ents:
        lines.append("Owner / abuse:")
        lines.extend(ents)
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def rdap_lookup(query: str) -> str:
        """Keyless WHOIS/RDAP lookup for a domain or IP (registrar, org, dates, nameservers).

        Uses rdap.org, which bootstraps to the authoritative registry. No API
        key. For a domain: registrar/registrant org, registration/expiry dates,
        nameservers, DNSSEC. For an IP/CIDR: network owner, range, country,
        abuse contact — useful to pivot an SSRF/exposed-host IP back to its org.

        Args:
            query: A domain (example.com) or an IP address.
        """
        query = query.strip().lower()
        if _is_ip(query):
            url = f"https://rdap.org/ip/{query}"
            is_ip = True
        else:
            query = _sanitize_domain(query)
            url = f"https://rdap.org/domain/{query}"
            is_ip = False

        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as http:
                resp = await http.get(url, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 404:
                    return f"No RDAP record for {query} (registry returned 404 — unregistered or not in RDAP)."
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return "Error: RDAP lookup timed out (30s)."
        except httpx.HTTPStatusError as e:
            return f"Error: RDAP returned HTTP {e.response.status_code} for {query}"
        except Exception as e:
            return f"Error querying RDAP: {e}"

        return _format_ip(data) if is_ip else _format_domain(data)
