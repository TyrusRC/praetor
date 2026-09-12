"""enrich_passive_dns — keyless passive-DNS aggregation.

Fans out to passive-DNS sources that need NO API key or registration —
AlienVault OTX, HackerTarget, RapidDNS — dedups to subdomains + resolved IPs
with first/last-seen where the source carries it. This is the keyless half of
what a theHarvester-style tool does; the key-gated sources (SecurityTrails,
VirusTotal, Shodan) are deliberately omitted — useless without a key the
operator rarely has.
"""

import re

import httpx
from mcp.server.fastmcp import FastMCP

from ._common import _sanitize_domain

# Each record: (hostname, ip, first_seen, last_seen, source). Blanks where absent.
_Record = tuple[str, str, str, str, str]


def _parse_otx(payload: dict, domain: str) -> list[_Record]:
    """AlienVault OTX /passive_dns → records."""
    out: list[_Record] = []
    for row in payload.get("passive_dns", []) or []:
        host = str(row.get("hostname", "")).strip().lower()
        if not host or not host.endswith(domain):
            continue
        out.append((
            host,
            str(row.get("address", "")).strip(),
            str(row.get("first", "")).strip(),
            str(row.get("last", "")).strip(),
            "otx",
        ))
    return out


def _parse_hackertarget(text: str, domain: str) -> list[_Record]:
    """HackerTarget hostsearch → CSV 'host,ip' lines (or an error/limit string)."""
    if not text or "error" in text.lower() or "API count exceeded" in text:
        return []
    out: list[_Record] = []
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) != 2:
            continue
        host, ip = parts[0].strip().lower(), parts[1].strip()
        if host.endswith(domain):
            out.append((host, ip, "", "", "hackertarget"))
    return out


_RAPIDDNS_ROW = re.compile(
    r"<td[^>]*>\s*([a-z0-9._-]+\.[a-z]{2,})\s*</td>\s*"
    r"<td[^>]*>\s*([0-9a-f:.]*)\s*</td>",
    re.IGNORECASE,
)


def _parse_rapiddns(html: str, domain: str) -> list[_Record]:
    """RapidDNS subdomain table → records (host in col 1, IP in col 2)."""
    out: list[_Record] = []
    for host, ip in _RAPIDDNS_ROW.findall(html or ""):
        host = host.strip().lower()
        if host.endswith(domain):
            out.append((host, ip.strip(), "", "", "rapiddns"))
    return out


def _merge(records: list[_Record]) -> dict[str, dict]:
    """Collapse records by hostname → {ips, first, last, sources}."""
    merged: dict[str, dict] = {}
    for host, ip, first, last, source in records:
        e = merged.setdefault(host, {"ips": set(), "first": "", "last": "", "sources": set()})
        if ip:
            e["ips"].add(ip)
        if first and (not e["first"] or first < e["first"]):
            e["first"] = first
        if last and last > e["last"]:
            e["last"] = last
        e["sources"].add(source)
    return merged


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def enrich_passive_dns(domain: str) -> str:
        """Keyless passive-DNS: subdomains + resolved IPs from OTX / HackerTarget / RapidDNS.

        Aggregates passive-DNS sources that need no API key, dedups by
        hostname, and reports resolved IPs plus first/last-seen where the
        source supplies it. Complements crt.sh (certs) and subfinder (active) —
        passive DNS surfaces hosts that never appear in CT logs and historical
        A-records for takeover / SSRF pivots. Degrades per source (a dead or
        rate-limited source is skipped, not fatal).

        Args:
            domain: Target apex domain (e.g. example.com).
        """
        domain = _sanitize_domain(domain)

        sources = {
            "otx": (f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", "json"),
            "hackertarget": (f"https://api.hackertarget.com/hostsearch/?q={domain}", "text"),
            "rapiddns": (f"https://rapiddns.io/subdomain/{domain}?full=1", "text"),
        }

        records: list[_Record] = []
        responded: list[str] = []
        failed: list[str] = []

        async with httpx.AsyncClient(
            timeout=30, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; recon)"},
        ) as http:
            for name, (url, kind) in sources.items():
                try:
                    resp = await http.get(url)
                    resp.raise_for_status()
                    if name == "otx":
                        recs = _parse_otx(resp.json(), domain)
                    elif name == "hackertarget":
                        recs = _parse_hackertarget(resp.text, domain)
                    else:
                        recs = _parse_rapiddns(resp.text, domain)
                    records.extend(recs)
                    responded.append(f"{name}({len(recs)})")
                except Exception as e:
                    failed.append(f"{name}: {type(e).__name__}")

        merged = _merge(records)
        if not merged:
            note = f" Sources tried: {', '.join(sources)}." if not responded else ""
            fail = f" Failed: {'; '.join(failed)}." if failed else ""
            return f"No passive-DNS records for {domain}.{note}{fail}"

        lines = [f"Passive DNS for {domain} ({len(merged)} hosts):", ""]
        for host in sorted(merged):
            e = merged[host]
            ips = ", ".join(sorted(e["ips"])) if e["ips"] else "-"
            seen = ""
            if e["first"] or e["last"]:
                seen = f"  seen {e['first'] or '?'}..{e['last'] or '?'}"
            lines.append(f"  {host}  [{ips}]{seen}  ({','.join(sorted(e['sources']))})")

        lines.append("")
        lines.append(f"Sources responded: {', '.join(responded) or 'none'}")
        if failed:
            lines.append(f"Sources failed: {'; '.join(failed)}")
        return "\n".join(lines)
