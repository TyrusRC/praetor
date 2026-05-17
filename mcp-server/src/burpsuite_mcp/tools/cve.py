"""CVE intelligence — match detected tech stack against known vulnerabilities."""

import json
import re
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Same Chrome 131 UA as the rest of the tool surface — keeps CVE lookups
# indistinguishable from a normal browser. Avoid identifying strings; some
# intel hosts (NVD especially) throttle or null-route tool UAs.
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


@lru_cache(maxsize=1)
def _load_tech_vulns() -> dict:
    """Load tech-specific vulnerability data from knowledge base."""
    path = KNOWLEDGE_DIR / "tech_vulns.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


_VERSION_RE = re.compile(r"[\d]+(?:\.[\d]+)*")


def _extract_version(tech_string: str) -> str:
    """Extract version number from tech string like 'Apache/2.4.49' or 'PHP 8.1.2'."""
    m = _VERSION_RE.search(tech_string)
    return m.group(0) if m else ""


def _version_tuple(v: str) -> tuple:
    """Convert version string to tuple of ints for correct numeric comparison."""
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def _version_in_range(version: str, range_key: str) -> bool:
    """Check if version matches a range key like '2.4.49', '8.5.0-8.5.80', or 'any'.

    Exact-segment match: `range_key='8.1'` matches `version='8.1'`, `'8.1.3'`,
    and `'8.1.99'`, but NOT `'8.10'` or `'8.100'`. Prior implementation used a
    bidirectional prefix-tuple match which treated `8.1` and `8.10` as equal.
    """
    if range_key == "any":
        return True
    if not version:
        return False
    try:
        ver = _version_tuple(version)
        if "-" in range_key:
            low, high = range_key.split("-", 1)
            return _version_tuple(low) <= ver <= _version_tuple(high)
        range_ver = _version_tuple(range_key)
        # Prefix match only — range_key segments must exactly equal the
        # corresponding prefix of `version`. Unequal segment count alone is
        # fine (8.1 matches 8.1.3) but per-segment numbers must be equal.
        if len(ver) < len(range_ver):
            return False
        return ver[:len(range_ver)] == range_ver
    except (ValueError, TypeError):
        # Fall back to string comparison if version format is unexpected.
        # Avoid the bidirectional prefix trap here too: only check the
        # documented range prefix matches the observed version.
        if "-" in range_key:
            low, high = range_key.split("-", 1)
            return low <= version <= high
        return version.startswith(range_key + ".") or version == range_key


def _match_tech_to_vulns(tech_items: list[str], tech_vulns: dict) -> list[dict]:
    """Match detected tech stack items against known vulnerability patterns."""
    matches = []
    technologies = tech_vulns.get("technologies", {})

    for tech in tech_items:
        tech_lower = tech.lower().strip()
        version = _extract_version(tech)

        for tech_name, tech_data in technologies.items():
            if tech_name.lower() not in tech_lower:
                continue

            # Match version-specific CVEs
            for ver_range, ver_data in tech_data.get("versions", {}).items():
                if _version_in_range(version, ver_range):
                    for cve in ver_data.get("cves", []):
                        tests = ver_data.get("tests", [])
                        matches.append({
                            "tech": tech,
                            "category": tech_name,
                            "vulnerability": cve,
                            "description": "; ".join(tests),
                            "severity": ver_data.get("severity", "MEDIUM").upper(),
                            "cve": cve,
                            "test_with": "; ".join(tests),
                            "search_query": f"{tech_name} {ver_range}",
                        })
                    # Also include tests without CVEs (like default cred checks)
                    if not ver_data.get("cves"):
                        tests = ver_data.get("tests", [])
                        for test in tests:
                            matches.append({
                                "tech": tech,
                                "category": tech_name,
                                "vulnerability": test,
                                "description": test,
                                "severity": ver_data.get("severity", "MEDIUM").upper(),
                                "cve": "",
                                "test_with": test,
                                "search_query": f"{tech_name} {ver_range}",
                            })

            # Include common issues (version-independent)
            for issue in tech_data.get("common_issues", []):
                matches.append({
                    "tech": tech,
                    "category": tech_name,
                    "vulnerability": issue,
                    "description": issue,
                    "severity": "MEDIUM",
                    "cve": "",
                    "test_with": "",
                    "search_query": f"{tech_name} {issue.split()[0]}",
                })

            # Include default paths as low-severity checks
            for path in tech_data.get("default_paths", []):
                matches.append({
                    "tech": tech,
                    "category": tech_name,
                    "vulnerability": f"Check path: {path}",
                    "description": f"Default/sensitive path for {tech_name}",
                    "severity": "LOW",
                    "cve": "",
                    "test_with": f"curl_request(url='https://TARGET{path}')",
                    "search_query": "",
                })

    return matches


def register(mcp: FastMCP):

    @mcp.tool()
    async def check_tech_vulns(
        session: str = "",
        index: int = -1,
        tech_stack: list[str] | None = None,
    ) -> str:
        """Match detected tech stack against known CVEs and misconfigurations.

        Args:
            session: Session name to auto-detect tech stack from
            index: Proxy history index to detect tech stack from
            tech_stack: Manual list of tech strings
        """
        tech_items = tech_stack or []

        # Auto-detect tech stack if not provided
        if not tech_items:
            if session:
                resp = await client.post("/api/session/request", json={
                    "session": session,
                    "method": "GET",
                    "path": "/",
                })
                if "error" not in resp:
                    idx = resp.get("proxy_index", resp.get("index", -1))
                    if idx >= 0:
                        tech_resp = await client.post("/api/analysis/tech-stack", json={"index": idx})
                        if "error" not in tech_resp:
                            tech_items = tech_resp.get("technologies", [])
                            server = tech_resp.get("server", "")
                            if server:
                                tech_items.append(server)
                            for fw in tech_resp.get("frameworks", []):
                                tech_items.append(fw)
            elif index >= 0:
                tech_resp = await client.post("/api/analysis/tech-stack", json={"index": index})
                if "error" not in tech_resp:
                    tech_items = tech_resp.get("technologies", [])
                    server = tech_resp.get("server", "")
                    if server:
                        tech_items.append(server)
                    for fw in tech_resp.get("frameworks", []):
                        tech_items.append(fw)

        if not tech_items:
            return "No tech stack detected. Provide tech_stack list, session name, or proxy history index."

        tech_vulns = _load_tech_vulns()
        if not tech_vulns:
            return "Tech vulnerability knowledge base not found."

        matches = _match_tech_to_vulns(tech_items, tech_vulns)

        if not matches:
            # Still useful — return NVD search suggestions
            lines = [f"No known vulns matched for: {', '.join(tech_items)}", ""]
            lines.append("Search suggestions (NVD/exploit-db):")
            for tech in tech_items[:5]:
                # Extract product name and version for search
                clean = tech.split("/")[0].split(" ")[0].lower()
                lines.append(f"  - NVD: https://nvd.nist.gov/vuln/search/results?query={clean}")
                lines.append(f"  - Exploit-DB: https://www.exploit-db.com/search?q={clean}")
            return "\n".join(lines)

        # Group by severity
        by_severity: dict[str, list[dict]] = {}
        for m in matches:
            sev = m["severity"]
            by_severity.setdefault(sev, []).append(m)

        lines = [f"Tech stack: {', '.join(tech_items)}", f"Matched {len(matches)} known vulnerabilities:", ""]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.append(f"[{sev}] ({len(items)})")
            for m in items:
                lines.append(f"  {m['vulnerability']}")
                if m["cve"]:
                    lines.append(f"    CVE: {m['cve']}")
                lines.append(f"    Tech: {m['tech']}")
                if m["description"]:
                    lines.append(f"    {m['description'][:200]}")
                if m["test_with"]:
                    lines.append(f"    Test: {m['test_with']}")
                lines.append("")

        # Add search suggestions for items without matches
        matched_techs = {m["tech"].lower() for m in matches}
        unmatched = [t for t in tech_items if t.lower() not in matched_techs]
        if unmatched:
            lines.append("Unmatched tech (search manually):")
            for tech in unmatched[:5]:
                clean = tech.split("/")[0].split(" ")[0].lower()
                lines.append(f"  - {tech}: https://nvd.nist.gov/vuln/search/results?query={clean}")

        return "\n".join(lines)

    @mcp.tool()
    async def lookup_cve(
        cve_id: str = "",
        cpe23: str = "",
        max_results: int = 20,
    ) -> str:
        """Fast CVE intel via Shodan CVEDB (free, no API key, ~200ms).

        Use this instead of `search_cve` when you have a concrete CVE id or
        CPE 2.3 string. Output includes EPSS exploitability probability and
        CISA Known-Exploited-Vulnerabilities (KEV) status — both absent from
        NVD. Pass either `cve_id` (single lookup) OR `cpe23` (list).

        Args:
            cve_id: e.g. 'CVE-2021-44228' (Log4Shell). Returns rich detail.
            cpe23: e.g. 'cpe:2.3:a:libpng:libpng:0.8'. Returns up to `max_results` CVEs.
            max_results: Cap for CPE lookups (default 20).
        """
        if cve_id and cpe23:
            return "Pass either cve_id OR cpe23, not both."
        if not cve_id and not cpe23:
            return "Provide cve_id (e.g. 'CVE-2024-0001') or cpe23 (e.g. 'cpe:2.3:a:vendor:product:version')."

        if cve_id:
            res = await _shodan_cve_lookup(cve_id)
            if isinstance(res, str):
                return f"Shodan CVEDB: {res}"
            lines = [f"{res['id']}  CVSS {res.get('cvss', '?')}  (v{res.get('cvss_version', '?')})"]
            epss = res.get("epss")
            if isinstance(epss, (int, float)):
                lines.append(f"EPSS: {epss * 100:.2f}% likelihood of exploitation in next 30d")
            flags = []
            if res.get("kev"):
                flags.append("CISA-KEV (Known Exploited)")
            if res.get("ransomware_campaign"):
                flags.append(f"Ransomware: {res['ransomware_campaign']}")
            if flags:
                lines.append("Flags: " + " | ".join(flags))
            if res.get("published"):
                lines.append(f"Published: {res['published'][:10]}")
            if res.get("propose_action"):
                lines.append(f"Action: {res['propose_action']}")
            summary = (res.get("summary") or "").replace("\n", " ").strip()
            if summary:
                lines.append("")
                lines.append(summary[:600])
            refs = res.get("references") or []
            if refs:
                lines.append("")
                lines.append("References:")
                for r in refs[:8]:
                    lines.append(f"  {r}")
            return "\n".join(lines)

        # cpe23 lookup
        res = await _shodan_cpe_lookup(cpe23, limit=max(1, min(max_results, 100)))
        if isinstance(res, str):
            return f"Shodan CVEDB: {res}"
        if not res:
            return f"No CVEs returned for {cpe23}"
        lines = [f"Shodan CVEDB matches for {cpe23} ({len(res)}):"]
        for c in res:
            epss = c.get("epss")
            epss_str = f"  EPSS {epss * 100:5.2f}%" if isinstance(epss, (int, float)) else ""
            kev = " [KEV]" if c.get("kev") else ""
            cvss = c.get("cvss") if c.get("cvss") is not None else "?"
            lines.append(f"  {c['id']}  CVSS {cvss}{epss_str}{kev}")
            summary = (c.get("summary") or "").replace("\n", " ").strip()
            if summary:
                lines.append(f"    {summary[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def search_cve(
        query: str,
        tech: str = "",
        live_lookup: bool = True,
        max_results: int = 10,
    ) -> str:
        """Search CVEs via live NVD 2.0 API lookup or offline search URLs.

        Args:
            query: Search query (CVE ID, product name, or keyword)
            tech: Optional technology context for targeted search
            live_lookup: Query NVD API live (default True); False for URLs only
            max_results: Max NVD results (default 10, max 50)
        """
        import urllib.parse
        q = urllib.parse.quote_plus(query)

        lines = [f"CVE Search for: {query}"]
        if tech:
            lines.append(f"Technology: {tech}")
        lines.append("")

        if live_lookup:
            structured = await _nvd_lookup(query, min(max(1, max_results), 50))
            if isinstance(structured, str):
                lines.append(f"NVD lookup failed: {structured}")
            else:
                lines.append(f"NVD results ({len(structured)}):")
                for c in structured:
                    cvss = c.get("cvss_score")
                    cvss_str = f" [CVSS {cvss}]" if cvss is not None else ""
                    lines.append(f"  {c['id']}{cvss_str} ({c.get('published', '?')[:10]})")
                    summary = c.get("summary", "").replace("\n", " ")[:220]
                    if summary:
                        lines.append(f"    {summary}")
                lines.append("")

        lines.append("Search URLs:")
        lines.append(f"  NVD: https://nvd.nist.gov/vuln/search/results?query={q}")
        lines.append(f"  Exploit-DB: https://www.exploit-db.com/search?q={q}")
        lines.append(f"  GitHub Advisory: https://github.com/advisories?query={q}")

        if query.upper().startswith("CVE-"):
            lines.append(f"  MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={query}")
            lines.append(f"  NVD Detail: https://nvd.nist.gov/vuln/detail/{query}")

        # Suggest nuclei templates if technology is known
        if tech:
            lines.append("")
            lines.append("Nuclei template suggestions:")
            tech_lower = tech.lower()
            if "apache" in tech_lower:
                lines.append("  nuclei -t cves/ -tags apache -u TARGET")
            elif "nginx" in tech_lower:
                lines.append("  nuclei -t cves/ -tags nginx -u TARGET")
            elif "spring" in tech_lower or "java" in tech_lower:
                lines.append("  nuclei -t cves/ -tags spring,java -u TARGET")
            elif "wordpress" in tech_lower:
                lines.append("  nuclei -t cves/ -tags wordpress -u TARGET")
                lines.append("  wpscan --url TARGET --api-token TOKEN")
            elif "php" in tech_lower:
                lines.append("  nuclei -t cves/ -tags php -u TARGET")
            else:
                lines.append(f"  nuclei -t cves/ -tags {tech_lower.split('/')[0].split(' ')[0]} -u TARGET")

        return "\n".join(lines)


# ─── Shodan CVEDB (free, no API key, fastest) ───────────────────────────────

_SHODAN_CVE_URL = "https://cvedb.shodan.io/cve/{cve_id}"
_SHODAN_CPE_URL = "https://cvedb.shodan.io/cves"


async def _shodan_cve_lookup(cve_id: str) -> dict | str:
    """Look up a single CVE on Shodan CVEDB (free, no key, ~200ms).

    Returns a dict with id, cvss, epss, kev, ransomware_campaign,
    propose_action, summary, references, published — richer than NVD because
    EPSS + KEV are baked in. Returns an error string on failure.
    """
    import httpx
    cve = cve_id.upper().strip()
    if not cve.startswith("CVE-"):
        return f"not a CVE id: {cve_id}"
    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_SHODAN_CVE_URL.format(cve_id=cve))
        if resp.status_code == 404:
            return f"not found in Shodan CVEDB: {cve}"
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 10s"
    except Exception as e:  # noqa: BLE001
        return str(e)[:150]

    return {
        "id": data.get("cve_id", cve),
        "summary": data.get("summary", ""),
        "cvss": data.get("cvss"),
        "cvss_version": data.get("cvss_version"),
        "epss": data.get("epss"),  # 0–1 probability of exploitation
        "kev": bool(data.get("kev")),  # CISA Known Exploited
        "ransomware_campaign": data.get("ransomware_campaign"),
        "propose_action": data.get("propose_action", ""),
        "references": data.get("references", [])[:10],
        "published": data.get("published_time", ""),
    }


async def _shodan_cpe_lookup(cpe23: str, limit: int = 20) -> list[dict] | str:
    """List CVEs for a CPE 2.3 string via Shodan CVEDB.

    cpe23 format: cpe:2.3:a:vendor:product:version  (e.g. cpe:2.3:a:libpng:libpng:0.8)
    """
    import httpx
    if not cpe23.startswith("cpe:2.3:"):
        return f"not a CPE 2.3 string: {cpe23}"
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_SHODAN_CPE_URL, params={"cpe23": cpe23})
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 15s"
    except Exception as e:  # noqa: BLE001
        return str(e)[:150]

    cves = data.get("cves", []) or []
    out: list[dict] = []
    for c in cves[:limit]:
        out.append({
            "id": c.get("cve_id", "?"),
            "cvss": c.get("cvss"),
            "epss": c.get("epss"),
            "kev": bool(c.get("kev")),
            "summary": (c.get("summary") or "")[:240],
            "published": c.get("published_time", ""),
        })
    return out


# ─── NVD API lookup ─────────────────────────────────────────────────────────

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _nvd_lookup(query: str, max_results: int) -> list[dict] | str:
    """Query NVD 2.0 API. Returns a list of CVE dicts or an error string.

    Direct call — NVD is a reference/intel database, not the target. Keeping
    it out of Burp proxy history avoids polluting the hunt audit trail.
    """
    import httpx
    params: dict[str, str | int]
    if query.upper().startswith("CVE-"):
        params = {"cveId": query.upper()}
    else:
        params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        async with httpx.AsyncClient(
            timeout=20,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_NVD_API_URL, params=params)
        if resp.status_code == 403:
            return "NVD returned 403 (rate-limited). Try again in a minute or set live_lookup=False."
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 20s"
    except Exception as e:  # noqa: BLE001 - surface any network/parse issue
        return str(e)[:150]

    vulns = data.get("vulnerabilities", [])
    results: list[dict] = []
    for item in vulns[:max_results]:
        cve = item.get("cve", {})
        desc_list = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in desc_list if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                break
        results.append({
            "id": cve.get("id", "?"),
            "published": cve.get("published", ""),
            "summary": summary,
            "cvss_score": score,
        })
    return results
