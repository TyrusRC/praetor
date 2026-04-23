"""CVE intelligence — match detected tech stack against known vulnerabilities."""

import json
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


@lru_cache(maxsize=1)
def _load_tech_vulns() -> dict:
    """Load tech-specific vulnerability data from knowledge base."""
    path = KNOWLEDGE_DIR / "tech_vulns.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _extract_version(tech_string: str) -> str:
    """Extract version number from tech string like 'Apache/2.4.49' or 'PHP 8.1.2'."""
    import re
    m = re.search(r'[\d]+(?:\.[\d]+)*', tech_string)
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
        """Match detected technology stack against known CVEs and misconfigurations.

        Checks the tech stack (from detect_tech_stack or manually provided) against
        the knowledge base of technology-specific vulnerabilities. Returns matching
        CVEs, misconfigurations, and suggested test commands.

        Three ways to provide tech data (pick one):
        1. session: auto-detect tech from session's base URL
        2. index: detect tech from a specific proxy history item
        3. tech_stack: provide a list of tech strings directly

        Args:
            session: Session name — will auto-detect tech stack from base URL
            index: Proxy history index — will detect tech stack from this response
            tech_stack: Manual list of tech strings (e.g. ['Apache/2.4.49', 'PHP/7.4', 'WordPress 5.8'])
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
    async def search_cve(
        query: str,
        tech: str = "",
        live_lookup: bool = True,
        max_results: int = 10,
    ) -> str:
        """Search CVEs by query — live NVD 2.0 API lookup by default.

        With `live_lookup=True` (default), queries NVD's JSON 2.0 API
        (services.nvd.nist.gov/rest/json/cves/2.0) through Burp's proxy and
        returns structured results (CVE id, summary, CVSS, published date).
        Set `live_lookup=False` for the offline variant that only emits
        search URLs (useful when NVD is rate-limiting or unreachable).

        Args:
            query: Search query (e.g. 'Apache 2.4.49', 'Spring4Shell', 'CVE-2021-44228')
            tech: Optional technology context for more targeted search
            live_lookup: Call NVD API and return structured CVE list (default True)
            max_results: Cap NVD results returned (default 10, max 50)
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
            headers={"User-Agent": "burpsuite-swiss-knife-mcp/cve-lookup"},
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
