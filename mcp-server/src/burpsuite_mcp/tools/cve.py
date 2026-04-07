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


def _match_tech_to_vulns(tech_items: list[str], tech_vulns: dict) -> list[dict]:
    """Match detected tech stack items against known vulnerability patterns."""
    matches = []
    contexts = tech_vulns.get("contexts", {})

    for tech in tech_items:
        tech_lower = tech.lower().strip()
        for ctx_name, ctx_data in contexts.items():
            ctx_lower = ctx_name.lower()
            # Match tech name against context (e.g., "Apache/2.4.49" matches "apache")
            keywords = ctx_data.get("keywords", [ctx_lower])
            if any(kw.lower() in tech_lower for kw in keywords):
                for vuln in ctx_data.get("vulnerabilities", []):
                    matches.append({
                        "tech": tech,
                        "category": ctx_name,
                        "vulnerability": vuln.get("name", ""),
                        "description": vuln.get("description", ""),
                        "severity": vuln.get("severity", "MEDIUM"),
                        "cve": vuln.get("cve", ""),
                        "test_with": vuln.get("test_with", ""),
                        "search_query": vuln.get("search_query", ""),
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
    ) -> str:
        """Generate CVE search URLs for manual research.

        Builds search links for NVD, Exploit-DB, and GitHub Advisory Database
        based on technology name, version, or keyword.

        Args:
            query: Search query (e.g. 'Apache 2.4.49', 'Spring4Shell', 'CVE-2021-44228')
            tech: Optional technology context for more targeted search
        """
        import urllib.parse
        q = urllib.parse.quote_plus(query)
        t = urllib.parse.quote_plus(tech) if tech else ""

        lines = [f"CVE Search for: {query}"]
        if tech:
            lines.append(f"Technology: {tech}")
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
