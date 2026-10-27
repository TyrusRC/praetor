"""get_hunt_plan: tech-stack-aware phased testing plan."""

from praetor import client
from praetor.tools.advisor._constants import TECH_PRIORITIES
from praetor.tools.advisor._helpers import detect_tech_from_headers


async def get_hunt_plan_impl(
    target_url: str,
    tech_stack: list[str] | None = None,
    known_endpoints: list[str] | None = None,
) -> str:
    techs = tech_stack or []

    # Auto-detect tech if not provided
    if not techs:
        try:
            data = await client.post("/api/http/curl", json={"url": target_url, "method": "GET"})
            if "error" not in data:
                headers = data.get("response_headers", [])
                techs = detect_tech_from_headers(headers)
                body = data.get("response_body", "").lower()
                if "angular" in body or "ng-app" in body: techs.append("angular")
                if "react" in body or "reactdom" in body: techs.append("react")
                if "graphql" in body or "/graphql" in body: techs.append("graphql")
                if "wordpress" in body or "wp-content" in body: techs.append("wordpress")
        except Exception:
            pass

    if not techs:
        techs = ["default"]

    # Build priority vuln list from tech stack
    vuln_priority = []
    seen = set()
    for tech in techs:
        for vuln in TECH_PRIORITIES.get(tech.lower(), TECH_PRIORITIES["default"]):
            if vuln not in seen:
                vuln_priority.append(vuln)
                seen.add(vuln)

    lines = [f"Hunt Plan for {target_url}"]
    lines.append(f"Tech detected: {', '.join(techs)}")
    lines.append(f"Priority vulns: {', '.join(vuln_priority[:8])}")
    lines.append("")

    # Phase 0: Edition gate — call once per session.
    lines.append("PHASE 0 — EDITION CHECK (do this FIRST, once per session):")
    lines.append("  0. check_pro_features()")
    lines.append("     → Confirms Pro vs Community. If Community: skip scan_url/")
    lines.append("       crawl_target/Collaborator-based tools and use the")
    lines.append("       MCP-side equivalents listed in that tool's output.")
    lines.append("")

    # Phase 1: Auto-scan (vigil web + groma network)
    lines.append("PHASE 1 — AUTO-SCAN (run both default engines first):")
    lines.append(f"  1. run_vigil(target='{target_url}', profile='thorough')")
    lines.append("     → Default web DAST: OWASP Top 10 + WSTG, 110+ detectors.")
    lines.append("       Covers SQLi/XSS/CMDi/SSTI/SSRF/XXE and more. Run FIRST.")
    lines.append(f"  2. run_groma(target='{target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url}')")
    lines.append("     → Default network scanner: full port range + CVE checks.")
    lines.append("       Finds non-web services, open ports, version-matched CVEs.")
    lines.append("       HTTP services found are bridged to the web lane.")
    lines.append("  3. import_scan_results(path=<vigil output>, fmt='vigil')")
    lines.append("     → Merge vigil findings into findings.json for the pipeline.")

    # THINK step: analyze auto-scan results before continuing
    lines.append("")
    lines.append("  THINK — before moving on, analyze what vigil + groma found:")
    lines.append("    - Which findings are CONFIRMED (exploit demonstrated)?")
    lines.append("    - Which are LEADS that need deeper testing (confirm_sqli, escalate_ssrf)?")
    lines.append("    - What ATTACK PATHS emerge? (SQLi→data dump, SSRF→IMDS creds, SSTI→RCE)")
    lines.append("    - What did groma reveal? (open ports → services to probe, CVEs to verify)")
    lines.append("    - Prioritize: confirm HIGH-impact leads FIRST, not more scanning.")
    lines.append("    Use: get_findings(domain, severity_min='medium', summary_only=True)")

    # Phase 2: Recon (fill gaps the auto-scans missed)
    lines.append("")
    lines.append("PHASE 2 — RECON (fill gaps auto-scans missed):")
    lines.append(f"  1. browser_crawl('{target_url}', max_pages=20)")
    lines.append("     → SPA routes and JS-rendered pages vigil may not crawl")
    lines.append("  2. detect_tech_stack(index=<first_200_response>)")
    lines.append("     → Confirm tech stack from proxy history")
    lines.append("  3. smart_analyze(index=<most_interesting_page>)")
    lines.append("     → Injection points, params, forms for manual testing")

    if "angular" in techs or "react" in techs:
        lines.append("  4. extract_js_secrets(index=<js_file>)")
        lines.append("     → JS frameworks often leak API keys and internal URLs")

    lines.append("")
    lines.append("  THINK — what does the tech stack + recon reveal?")
    lines.append("    - Which vuln classes are MOST LIKELY on this stack?")
    lines.append("    - What is the highest-value endpoint (auth, payment, admin, API)?")
    lines.append("    - Any auth endpoints → test_auth_matrix is higher ROI than more scanning.")
    lines.append("    - Any API spec found → fuzz_api_schema before manual probing.")

    # Phase 3: Targeted probe (beyond what vigil covers)
    lines.append("")
    lines.append("PHASE 3 — TARGETED PROBE (classes vigil does not cover):")
    lines.append("  vigil covers injection + headers + CVEs. Use auto_probe for:")
    lines.append("  - Business logic, auth matrix, race conditions, mass assignment")
    lines.append("  - KB edge cases vigil does not test")
    for i, vuln in enumerate(vuln_priority[:6], 1):
        lines.append(f"  {i}. {vuln}: auto_probe(categories=['{vuln}'])")

    # Phase 4: Specialized tests
    lines.append("")
    lines.append("PHASE 4 — SPECIALIZED TESTS:")
    if "graphql" in techs:
        lines.append("  - test_graphql() — introspection, batch queries, field suggestions")
    if any(t in techs for t in ["api", "default", "node", "express", "rails", "django"]):
        lines.append("  - test_auth_matrix() — IDOR across auth states (if multiple roles)")
        lines.append("  - test_cors() — CORS misconfiguration")
    lines.append("  - discover_common_files() — .git, .env, debug, actuator")
    lines.append("  - test_jwt() — if JWT tokens found in cookies/headers")

    lines.append("")
    lines.append("  THINK — before verification, review all findings:")
    lines.append("    - Which findings have REAL IMPACT (data access, account control, RCE)?")
    lines.append("    - Which can be CHAINED for higher impact? (redirect→token theft, info→SSRF)")
    lines.append("    - What does a TRIAGER need to accept this? (clear PoC, impact statement)")
    lines.append("    - Drop findings that are noise. A confirmed HIGH > three unverified MEDIUMs.")
    lines.append("    Use: propose_chains(domain) to find chain opportunities.")

    # Phase 5: Verify
    lines.append("")
    lines.append("PHASE 5 — VERIFY (for each suspected finding):")
    lines.append("  1. Reproduce 3x with session_request()")
    lines.append("  2. Compare against baseline response")
    lines.append("  3. Check 7-Question Gate before reporting")

    lines.append("")
    lines.append("TOKEN TIP: Use extract_regex/extract_headers instead of get_request_detail to save tokens on large responses.")

    lines.append("")
    lines.append("DISCIPLINE (read operational-discipline.md + noise-budget.md once — this plan does not restate them):")
    lines.append("  - A phase-2 line is a reason to look, not a license to fire every payload blind.")
    lines.append("    State a one-line hypothesis first: \"I expect <observable> if <vuln> at <param>\".")
    lines.append("  - Stop a category by REASONING (KB cleared + tech-stack match, WAF-filtered -> switch")
    lines.append("    technique don't abandon, 30-probes-at-c<0.30 -> document negative + pivot), not by")
    lines.append("    a fixed probe count.")
    lines.append("  - Replay before save (Rule 10a). One verified bug beats ten anomalies.")

    return "\n".join(lines)
