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

    # Phase 1: Recon
    lines.append("PHASE 1 — RECON (do these first, in order):")
    lines.append(f"  1. browser_crawl('{target_url}', max_pages=20)")
    lines.append("     → Populates proxy history through Burp proxy")
    lines.append("  2. get_proxy_history(limit=50)")
    lines.append("     → Review captured endpoints")
    lines.append("  3. detect_tech_stack(index=<first_200_response>)")
    lines.append("     → Confirm tech stack detection")
    lines.append("  4. smart_analyze(index=<most_interesting_page>)")
    lines.append("     → Get injection points, params, forms")

    if "angular" in techs or "react" in techs:
        lines.append("  5. extract_js_secrets(index=<js_file>)")
        lines.append("     → JS frameworks often leak API keys and internal URLs")

    # Phase 2: Probe
    lines.append("")
    lines.append("PHASE 2 — PROBE (test these vuln categories in order):")
    for i, vuln in enumerate(vuln_priority[:6], 1):
        tool = "auto_probe" if i <= 3 else "probe_endpoint"
        lines.append(f"  {i}. {vuln}: use {tool} with category='{vuln}'")

    # Phase 3: Specialized tests
    lines.append("")
    lines.append("PHASE 3 — SPECIALIZED TESTS:")
    if "graphql" in techs:
        lines.append("  - test_graphql() — introspection, batch queries, field suggestions")
    if any(t in techs for t in ["api", "default", "node", "express", "rails", "django"]):
        lines.append("  - test_auth_matrix() — IDOR across auth states (if multiple roles)")
        lines.append("  - test_cors() — CORS misconfiguration")
    lines.append("  - discover_common_files() — .git, .env, debug, actuator")
    lines.append("  - test_jwt() — if JWT tokens found in cookies/headers")

    # Phase 4: Verify
    lines.append("")
    lines.append("PHASE 4 — VERIFY (for each suspected finding):")
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
