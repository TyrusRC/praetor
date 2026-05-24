"""Tech-stack -> CVE pipeline tools — check_tech_vulns, map_tech_to_cves."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from .match import _load_tech_vulns, _match_tech_to_vulns
from .shodan import _shodan_cves_query


def register(mcp: FastMCP) -> None:

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
            lines = [f"No known vulns matched for: {', '.join(tech_items)}", ""]
            lines.append("Search suggestions (NVD/exploit-db):")
            for tech in tech_items[:5]:
                clean = tech.split("/")[0].split(" ")[0].lower()
                lines.append(f"  - NVD: https://nvd.nist.gov/vuln/search/results?query={clean}")
                lines.append(f"  - Exploit-DB: https://www.exploit-db.com/search?q={clean}")
            return "\n".join(lines)

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

        matched_techs = {m["tech"].lower() for m in matches}
        unmatched = [t for t in tech_items if t.lower() not in matched_techs]
        if unmatched:
            lines.append("Unmatched tech (search manually):")
            for tech in unmatched[:5]:
                clean = tech.split("/")[0].split(" ")[0].lower()
                lines.append(f"  - {tech}: https://nvd.nist.gov/vuln/search/results?query={clean}")

        return "\n".join(lines)

    @mcp.tool()
    async def map_tech_to_cves(
        target: str,
        save_intel: bool = True,
        max_cves_per_tech: int = 5,
        is_kev_only: bool = False,
        sort_by_epss: bool = True,
    ) -> str:
        """Pipeline: httpx tech-detect (wappalyzergo) -> Shodan CVEDB CVE lookup -> save_target_intel(profile).

        One-shot asset mapping + CVE intel. Detects technologies via the
        wappalyzergo-powered `httpx -tech-detect`, normalises each detected
        product to a Shodan CVEDB product slug, fetches CVEs (sorted by EPSS
        by default so the operator sees most-exploited first), and persists
        the tech stack into `.burp-intel/<domain>/profile.json` for the
        advisor + assess_finding to use later.

        Args:
            target: Single URL (https://example.com)
            save_intel: True (default) -> persist detected tech to profile.json
            max_cves_per_tech: Per-product CVE cap (default 5)
            is_kev_only: True -> restrict CVE list to CISA-KEV. Use this on
                short-engagement triage to focus on actively-exploited bugs.
            sort_by_epss: True (default) -> highest-EPSS CVEs first.
        """
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        try:
            from burpsuite_mcp.tools.recon._common import (
                _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL,
            )
            if not _check_tool("httpx"):
                return (
                    "Error: httpx (ProjectDiscovery) not installed.\n"
                    "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
                )
            cmd = [
                "httpx", "-u", target, "-tech-detect", "-silent", "-no-color",
                "-status-code", "-content-length", "-title",
                "-follow-redirects",
                "-H", f"User-Agent: {_USER_AGENT}",
                "-http-proxy", BURP_PROXY_URL,
                "-timeout", "10",
            ]
            stdout, stderr, code = await _run_cmd(cmd, timeout=90)
            if not stdout.strip():
                return f"httpx returned no output for {target} (exit {code}). " \
                       f"Verify httpx in ~/go/bin and target reachable."
        except Exception as e:
            return f"httpx invocation failed: {e}"

        techs: list[str] = []
        for line in stdout.splitlines():
            if "[" not in line:
                continue
            brackets = []
            buf = ""
            depth = 0
            for ch in line:
                if ch == "[":
                    depth += 1
                    if depth == 1:
                        buf = ""
                        continue
                if ch == "]":
                    if depth == 1:
                        brackets.append(buf)
                    depth -= 1
                    continue
                if depth >= 1:
                    buf += ch
            if brackets:
                candidate = brackets[-1]
                for t in candidate.split(","):
                    t = t.strip()
                    if t and not t.isdigit() and not t.startswith("http"):
                        techs.append(t)

        techs = sorted(set(techs))
        if not techs:
            return f"No technologies detected on {target}. Output: {stdout[:300]}"

        import asyncio as _asyncio
        tech_product_pairs: list[tuple[str, str]] = []
        for tech in techs:
            product = tech.split(":")[0].split("/")[0].strip().lower()
            if not product:
                continue
            tech_product_pairs.append((tech, product))

        async def _one(product: str):
            params: dict[str, str] = {"product": product}
            if is_kev_only:
                params["is_kev"] = "true"
            if sort_by_epss:
                params["sort_by_epss"] = "true"
            return await _shodan_cves_query(params, limit=max_cves_per_tech)

        cve_results = await _asyncio.gather(
            *(_one(p) for _t, p in tech_product_pairs),
            return_exceptions=True,
        )
        per_tech_results: list[tuple[str, list[dict] | str]] = []
        for (tech, _product), result in zip(tech_product_pairs, cve_results):
            if isinstance(result, Exception):
                per_tech_results.append((tech, f"lookup raised: {result}"))
            else:
                per_tech_results.append((tech, result))

        lines = [f"map_tech_to_cves for {target}:"]
        lines.append(f"  detected: {', '.join(techs)}")
        lines.append("")
        critical_total = 0
        kev_total = 0
        for tech, cves in per_tech_results:
            if isinstance(cves, str):
                lines.append(f"  {tech}: lookup failed ({cves[:80]})")
                continue
            if not cves:
                lines.append(f"  {tech}: no Shodan CVEDB matches")
                continue
            lines.append(f"  {tech} ({len(cves)} CVEs):")
            for c in cves:
                epss = c.get("epss")
                epss_str = f"  EPSS {epss * 100:5.2f}%" if isinstance(epss, (int, float)) else ""
                kev = " [KEV]" if c.get("kev") else ""
                if c.get("kev"):
                    kev_total += 1
                cvss = c.get("cvss") if c.get("cvss") is not None else "?"
                if isinstance(cvss, (int, float)) and cvss >= 9.0:
                    critical_total += 1
                lines.append(f"    {c['id']}  CVSS {cvss}{epss_str}{kev}")
                summary = (c.get("summary") or "").strip().replace("\n", " ")
                if summary:
                    lines.append(f"      {summary[:160]}")

        lines.append("")
        lines.append(f"  Summary: {critical_total} CVSS>=9, {kev_total} KEV")

        if save_intel:
            try:
                from burpsuite_mcp.tools.intel._internals import _intel_path, _ensure_dir, _atomic_write_json
                import json as _json
                profile_path = _intel_path(host) / "profile.json"
                _ensure_dir(host)
                existing = {}
                if profile_path.exists():
                    try:
                        existing = _json.loads(profile_path.read_text())
                    except Exception:
                        existing = {}
                existing["tech_stack"] = techs
                existing["cve_summary"] = {
                    "critical_count": critical_total,
                    "kev_count": kev_total,
                    "last_scan": target,
                }
                _atomic_write_json(profile_path, existing)
                lines.append(f"  Intel saved: {profile_path}")
            except Exception as e:
                lines.append(f"  Intel save failed: {e}")

        lines.append("")
        lines.append("Next: lookup_cve(cve_id=<id>) for any high-EPSS / KEV entry above to get full detail + references.")
        return "\n".join(lines)
