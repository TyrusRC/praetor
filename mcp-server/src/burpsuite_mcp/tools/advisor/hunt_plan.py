"""get_hunt_plan: tech-stack-aware phased testing plan."""

from burpsuite_mcp import client
from burpsuite_mcp.tools.advisor._constants import TECH_PRIORITIES
from burpsuite_mcp.tools.advisor._helpers import detect_tech_from_headers


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
    lines.append(f"  0. check_pro_features()")
    lines.append(f"     → Confirms Pro vs Community. If Community: skip scan_url/")
    lines.append(f"       crawl_target/Collaborator-based tools and use the")
    lines.append(f"       MCP-side equivalents listed in that tool's output.")
    lines.append("")

    # Phase 1: Recon
    lines.append("PHASE 1 — RECON (do these first, in order):")
    lines.append(f"  1. browser_crawl('{target_url}', max_pages=20)")
    lines.append(f"     → Populates proxy history through Burp proxy")
    lines.append(f"  2. get_proxy_history(limit=50)")
    lines.append(f"     → Review captured endpoints")
    lines.append(f"  3. detect_tech_stack(index=<first_200_response>)")
    lines.append(f"     → Confirm tech stack detection")
    lines.append(f"  4. smart_analyze(index=<most_interesting_page>)")
    lines.append(f"     → Get injection points, params, forms")

    if "angular" in techs or "react" in techs:
        lines.append(f"  5. extract_js_secrets(index=<js_file>)")
        lines.append(f"     → JS frameworks often leak API keys and internal URLs")

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
        lines.append(f"  - test_graphql() — introspection, batch queries, field suggestions")
    if any(t in techs for t in ["api", "default", "node", "express", "rails", "django"]):
        lines.append(f"  - test_auth_matrix() — IDOR across auth states (if multiple roles)")
        lines.append(f"  - test_cors() — CORS misconfiguration")
    lines.append(f"  - discover_common_files() — .git, .env, debug, actuator")
    lines.append(f"  - test_jwt() — if JWT tokens found in cookies/headers")

    # Phase 4: Verify
    lines.append("")
    lines.append("PHASE 4 — VERIFY (for each suspected finding):")
    lines.append(f"  1. Reproduce 3x with session_request()")
    lines.append(f"  2. Compare against baseline response")
    lines.append(f"  3. Check 7-Question Gate before reporting")

    lines.append("")
    lines.append("TOKEN TIP: Use extract_regex/extract_headers instead of get_request_detail to save tokens on large responses.")

    return "\n".join(lines)
