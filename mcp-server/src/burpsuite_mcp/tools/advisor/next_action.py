"""get_next_action: single-best-next-action selector."""

from burpsuite_mcp.tools.advisor._constants import TECH_PRIORITIES


async def get_next_action_impl(
    target_url: str,
    completed_phases: list[str] | None = None,
    findings_count: int = 0,
    tested_params: list[str] | None = None,
    tech_stack: list[str] | None = None,
) -> str:
    completed = set(completed_phases or [])
    techs = tech_stack or ["default"]

    if "recon" not in completed:
        return (
            f"NEXT: Recon is not complete. Run:\n"
            f"  browser_crawl('{target_url}', max_pages=20)\n"
            f"Then:\n"
            f"  get_proxy_history(limit=50)\n"
            f"Then mark recon complete."
        )

    if "probe" not in completed:
        # Get priority vulns for tech stack
        vulns = []
        for tech in techs:
            vulns.extend(TECH_PRIORITIES.get(tech.lower(), TECH_PRIORITIES["default"]))
        vulns = list(dict.fromkeys(vulns))[:5]  # dedupe, top 5

        return (
            f"NEXT: Run knowledge-driven probes. Execute:\n"
            f"  auto_probe(session='<your_session>', categories={vulns[:3]})\n"
            f"This tests the top-priority vuln categories for {', '.join(techs)} tech stack.\n"
            f"After probing, mark probe complete."
        )

    if "exploit" not in completed:
        if findings_count > 0:
            return (
                f"NEXT: You have {findings_count} suspected findings. Verify them:\n"
                f"  For each finding, use session_request() to reproduce 3x.\n"
                f"  Compare against baseline with compare_responses().\n"
                f"  If IDOR suspected: test_auth_matrix()\n"
                f"  If blind vuln: auto_collaborator_test()"
            )
        return (
            f"NEXT: No findings yet from probing. Try specialized tests:\n"
            f"  1. discover_common_files() — sensitive file exposure\n"
            f"  2. test_cors() — CORS misconfiguration\n"
            f"  3. test_jwt() — JWT vulnerabilities (if tokens present)\n"
            f"  4. fuzz_parameter() with smart_payloads=True on highest-risk params"
        )

    from urllib.parse import urlparse
    parsed_host = urlparse(target_url).hostname
    if not parsed_host:
        parsed_host = target_url.split("/", 1)[0] or target_url
    return (
        f"NEXT: All phases complete with {findings_count} findings.\n"
        f"  - save_finding() for each confirmed finding\n"
        f"  - generate_report('{parsed_host}')\n"
        f"  - save_target_intel() to persist for future sessions"
    )
