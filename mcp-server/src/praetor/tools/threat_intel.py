"""Threat-intel / OSINT enrichment — VirusTotal + Shodan (free-tier friendly).

Passive enrichment that complements the recon lane (query_crtsh, analyze_dns,
enrich_passive_dns, run_uncover, run_theharvester). These are READ-ONLY lookups
against public reputation/exposure APIs; they do not touch the target, so they
call the API directly (not through Burp).

Keyless by default, keys only enhance:
  - shodan_host: uses Shodan's FREE no-key InternetDB by default; richer when
    SHODAN_API_KEY is set.
  - vt_lookup: needs VT_API_KEY (VirusTotal free public API, ~4 req/min).

Where to put keys: the MCP server's env block (Codex config.toml, Claude .mcp.json,
dsh cordis.yml) or a .env file. See .env.example for the full free-key list.
"""

from __future__ import annotations

import base64
import os
import re

import httpx

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}([a-fA-F0-9]{8})?([a-fA-F0-9]{24})?$")  # md5/sha1/sha256


def _detect_kind(target: str) -> str:
    t = target.strip()
    if _IP_RE.match(t):
        return "ip"
    if t.startswith(("http://", "https://")):
        return "url"
    if _HASH_RE.match(t) and len(t) in (32, 40, 64):
        return "hash"
    return "domain"


async def _get(url: str, headers: dict | None = None, params: dict | None = None,
               timeout: int = 20) -> tuple[dict | None, str]:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(url, headers=headers or {}, params=params or {})
            if r.status_code == 404:
                return None, "not found (404)"
            if r.status_code in (401, 403):
                return None, f"auth rejected ({r.status_code}) — check the API key"
            if r.status_code == 429:
                return None, "rate limited (429) — free tier; slow down"
            r.raise_for_status()
            return r.json(), ""
    except (httpx.HTTPError, ValueError) as e:
        return None, f"request error: {e}"


def register(mcp) -> None:

    @mcp.tool()
    async def vt_lookup(target: str, kind: str = "auto") -> dict:
        """VirusTotal reputation lookup for a domain / IP / URL / file-hash.

        Returns the detection stats (malicious / suspicious / harmless), reputation,
        and categories — a fast "is this known-bad / what is this" check for a host,
        an IP found in recon, or a dropped sample. Needs VT_API_KEY (free public API,
        rate-limited). Benign, read-only, does not touch the target.

        Args:
            target: domain, IP, URL, or file hash (md5/sha1/sha256).
            kind: auto (default) | domain | ip | url | hash.
        """
        key = os.environ.get("VT_API_KEY", "").strip()
        if not key:
            return {"error": "VT_API_KEY not set (VirusTotal free public API). "
                             "Get one at https://www.virustotal.com/gui/my-apikey, "
                             "then set VT_API_KEY. Optional enhancer — recon runs without it."}
        k = kind if kind != "auto" else _detect_kind(target)
        t = target.strip()
        if k == "domain":
            path = f"domains/{t}"
        elif k == "ip":
            path = f"ip_addresses/{t}"
        elif k == "hash":
            path = f"files/{t}"
        elif k == "url":
            uid = base64.urlsafe_b64encode(t.encode()).decode().rstrip("=")
            path = f"urls/{uid}"
        else:
            return {"error": f"unknown kind '{kind}'"}
        data, err = await _get(f"https://www.virustotal.com/api/v3/{path}",
                               headers={"x-apikey": key})
        if err:
            return {"error": f"VirusTotal: {err}", "target": t, "kind": k}
        attr = (data or {}).get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        out = {
            "target": t, "kind": k,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "verdict": "malicious" if stats.get("malicious", 0) else (
                "suspicious" if stats.get("suspicious", 0) else "clean/unknown"),
        }
        if attr.get("categories"):
            out["categories"] = sorted(set(attr["categories"].values()))[:8]
        if k == "domain" and attr.get("last_dns_records"):
            out["dns"] = [f'{r.get("type")}:{r.get("value")}'
                          for r in attr["last_dns_records"][:8]]
        if k == "ip":
            out["as_owner"] = attr.get("as_owner")
            out["country"] = attr.get("country")
        return out

    @mcp.tool()
    async def shodan_host(ip: str) -> dict:
        """Shodan host exposure for an IP — open ports, CPEs, hostnames, known CVEs.

        Keyless by default: uses Shodan's FREE InternetDB (no key). If SHODAN_API_KEY
        is set, uses the full Shodan host API for richer data (org, OS, per-port
        banners). Benign, read-only, does not touch the target — the data is Shodan's
        prior scan. Pair with run_nmap to confirm live.

        Args:
            ip: target IPv4 address.
        """
        ip = ip.strip()
        if not _IP_RE.match(ip):
            return {"error": "shodan_host needs an IPv4 address"}
        key = os.environ.get("SHODAN_API_KEY", "").strip()
        if key:
            data, err = await _get(f"https://api.shodan.io/shodan/host/{ip}",
                                   params={"key": key})
            if not err and data:
                return {
                    "ip": ip, "source": "shodan-api",
                    "ports": sorted(data.get("ports", [])),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org"), "os": data.get("os"),
                    "cpes": sorted({c for d in data.get("data", []) for c in d.get("cpe", [])})[:20],
                    "vulns": sorted(data.get("vulns", []))[:30],
                    "tags": data.get("tags", []),
                }
            # fall through to the keyless source on a key error
        data, err = await _get(f"https://internetdb.shodan.io/{ip}")
        if err:
            return {"ip": ip, "error": f"Shodan: {err}"}
        return {
            "ip": ip, "source": "internetdb (keyless)",
            "ports": sorted((data or {}).get("ports", [])),
            "hostnames": (data or {}).get("hostnames", []),
            "cpes": (data or {}).get("cpes", [])[:20],
            "vulns": sorted((data or {}).get("vulns", []))[:30],
            "tags": (data or {}).get("tags", []),
            "note": "" if key else "set SHODAN_API_KEY for org/OS/banners (free key enhances this).",
        }

    @mcp.tool()
    async def otx_lookup(target: str, kind: str = "auto") -> dict:
        """AlienVault OTX enrichment for a domain / IP — passive DNS, related URLs, malware.

        Pulls OTX's community threat intel: passive-DNS records, URLs seen, and
        malware samples tied to the indicator — good for expanding a recon target or
        checking if an IP is tied to known badness. Needs OTX_API_KEY (free at
        otx.alienvault.com). Benign, read-only.

        Args:
            target: domain or IPv4.
            kind: auto (default) | domain | ip.
        """
        key = os.environ.get("OTX_API_KEY", "").strip()
        if not key:
            return {"error": "OTX_API_KEY not set (AlienVault OTX, free at "
                             "https://otx.alienvault.com/api). Optional enhancer."}
        k = kind if kind != "auto" else _detect_kind(target)
        t = target.strip()
        seg = "IPv4" if k == "ip" else "domain"
        base = f"https://otx.alienvault.com/api/v1/indicators/{seg}/{t}"
        hdr = {"X-OTX-API-KEY": key}
        general, gerr = await _get(f"{base}/general", headers=hdr)
        if gerr:
            return {"error": f"OTX: {gerr}", "target": t, "kind": k}
        pdns, _ = await _get(f"{base}/passive_dns", headers=hdr)
        out = {"target": t, "kind": k,
               "pulse_count": (general or {}).get("pulse_info", {}).get("count", 0),
               "pulses": [p.get("name") for p in
                          (general or {}).get("pulse_info", {}).get("pulses", [])[:6]]}
        recs = (pdns or {}).get("passive_dns", [])
        out["passive_dns"] = [f'{r.get("hostname") or r.get("address")}' for r in recs[:10]]
        return out

    @mcp.tool()
    async def greynoise_lookup(ip: str) -> dict:
        """GreyNoise: is this IP internet background-noise (a mass scanner) or targeted?

        Classifies an IP as benign / malicious / unknown and whether it is common
        internet noise (RIOT = known benign service). Use it to triage recon IPs —
        drop the background scanners, focus on the real ones. Needs GREYNOISE_API_KEY
        (free Community key at greynoise.io). Benign, read-only.

        Args:
            ip: target IPv4 address.
        """
        ip = ip.strip()
        if not _IP_RE.match(ip):
            return {"error": "greynoise_lookup needs an IPv4 address"}
        key = os.environ.get("GREYNOISE_API_KEY", "").strip()
        if not key:
            return {"error": "GREYNOISE_API_KEY not set (free Community key at "
                             "https://viz.greynoise.io/account/api-key). Optional."}
        data, err = await _get(f"https://api.greynoise.io/v3/community/{ip}",
                               headers={"key": key})
        if err:
            return {"ip": ip, "error": f"GreyNoise: {err}"}
        d = data or {}
        return {"ip": ip, "noise": d.get("noise"), "riot": d.get("riot"),
                "classification": d.get("classification"), "name": d.get("name"),
                "last_seen": d.get("last_seen"), "link": d.get("link")}

    @mcp.tool()
    async def abuseipdb_lookup(ip: str, max_age_days: int = 90) -> dict:
        """AbuseIPDB reputation for an IP — abuse-confidence score + report count.

        Tells you how often an IP was reported for abuse (scanning, brute force,
        malware). Needs ABUSEIPDB_API_KEY (free tier at abuseipdb.com). Benign,
        read-only.

        Args:
            ip: target IPv4 address.
            max_age_days: how far back to count reports (default 90).
        """
        ip = ip.strip()
        if not _IP_RE.match(ip):
            return {"error": "abuseipdb_lookup needs an IPv4 address"}
        key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        if not key:
            return {"error": "ABUSEIPDB_API_KEY not set (free tier at "
                             "https://www.abuseipdb.com/register). Optional."}
        data, err = await _get("https://api.abuseipdb.com/api/v2/check",
                               headers={"Key": key, "Accept": "application/json"},
                               params={"ipAddress": ip, "maxAgeInDays": max_age_days})
        if err:
            return {"ip": ip, "error": f"AbuseIPDB: {err}"}
        d = (data or {}).get("data", {})
        return {"ip": ip, "abuse_confidence": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"), "country": d.get("countryCode"),
                "isp": d.get("isp"), "domain": d.get("domain"),
                "is_tor": d.get("isTor"), "usage_type": d.get("usageType")}

    @mcp.tool()
    async def urlscan_search(query: str, limit: int = 10) -> dict:
        """URLScan.io search (KEYLESS) — find prior scans for a domain / IP / URL.

        Searches urlscan.io's public scan archive to surface related page URLs, the
        IPs and servers a domain resolved to, and sibling domains — subdomain and
        infra discovery with no key. A URLSCAN_API_KEY only adds higher rate limits
        and private scans (not needed for search). Benign, read-only.

        Args:
            query: a urlscan query — a bare domain works (e.g. 'example.com'), or a
                field query like 'page.ip:1.2.3.4' / 'domain:example.com'.
            limit: max results (default 10).
        """
        q = query.strip()
        if "." in q and ":" not in q and " " not in q:
            q = f"domain:{q}"            # bare host -> domain: query
        hdr = {}
        apikey = os.environ.get("URLSCAN_API_KEY", "").strip()
        if apikey:
            hdr["API-Key"] = apikey
        data, err = await _get("https://urlscan.io/api/v1/search/",
                               headers=hdr, params={"q": q, "size": min(limit, 100)})
        if err:
            return {"query": q, "error": f"urlscan: {err}"}
        results = (data or {}).get("results", [])
        out = []
        for r in results[:limit]:
            page = r.get("page", {})
            out.append({"url": (r.get("task", {}) or {}).get("url"),
                        "ip": page.get("ip"), "server": page.get("server"),
                        "domain": page.get("domain"), "country": page.get("country")})
        return {"query": q, "total": (data or {}).get("total", len(out)),
                "results": out, "source": "urlscan (keyless)"}

    @mcp.tool()
    async def ti_status() -> dict:
        """Report which threat-intel / OSINT API keys are configured (shape only).

        Shows which enrichers are live vs keyless. All are optional — the recon lane
        runs without any of them. Set keys in the MCP server's env block or a .env
        file; see .env.example for the free-key list and where to get each.
        """
        def present(name: str) -> str:
            return "set" if os.environ.get(name, "").strip() else "(unset)"
        return {
            "keyless_always_on": ["shodan_host (InternetDB)", "urlscan_search",
                                  "query_crtsh", "analyze_dns", "rdap_lookup",
                                  "fetch_wayback_urls"],
            "keyed_enhancers": {
                "VT_API_KEY (VirusTotal)": present("VT_API_KEY"),
                "SHODAN_API_KEY (Shodan full)": present("SHODAN_API_KEY"),
                "OTX_API_KEY (AlienVault OTX)": present("OTX_API_KEY"),
                "GREYNOISE_API_KEY (GreyNoise)": present("GREYNOISE_API_KEY"),
                "ABUSEIPDB_API_KEY (AbuseIPDB)": present("ABUSEIPDB_API_KEY"),
                "URLSCAN_API_KEY (urlscan, rate-limit only)": present("URLSCAN_API_KEY"),
                "HIBP_API_KEY (HaveIBeenPwned)": present("HIBP_API_KEY"),
                "CHAOS_KEY (ProjectDiscovery)": present("CHAOS_KEY"),
            },
            "note": "All keys are optional and free-tier. Recon runs keyless; keys only enhance.",
        }
