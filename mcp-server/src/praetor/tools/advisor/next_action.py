"""get_next_action: findings-first next-action selector.

The priority: act on what was FOUND before scanning more. A confirmed lead
(SQLi, SSRF, SSTI) gets a confirm/escalate call. Only when no leads remain
does the advisor recommend more scanning.
"""

from praetor.tools.advisor._constants import TECH_PRIORITIES

# Vuln class → confirmation tool. The action for a lead is the tool that
# proves or disproves it, not "keep scanning."
_CONFIRM_TOOLS: dict[str, str] = {
    "sqli": "confirm_sqli", "sql_injection": "confirm_sqli",
    "xss": "confirm_xss", "xss_reflected": "confirm_xss", "xss_stored": "confirm_xss",
    "ssrf": "confirm_ssrf", "ssrf_blind": "confirm_ssrf",
    "ssti": "confirm_ssti", "ssti_blind": "confirm_ssti",
    "xxe": "confirm_xxe", "xxe_blind": "confirm_xxe",
    "rce": "confirm_rce", "command_injection": "confirm_rce",
    "nosql": "confirm_nosql", "nosqli": "confirm_nosql",
    "idor": "confirm_idor", "bola": "confirm_idor",
    "race_condition": "confirm_race_condition",
    "ldap": "confirm_ldap", "xpath": "confirm_xpath",
    "xslt": "confirm_xslt", "ssi": "confirm_ssi",
    "expression": "confirm_expression",
}

# Vuln class → escalation tool (for already-confirmed findings).
_ESCALATE_TOOLS: dict[str, str] = {
    "sqli": "escalate_sqli", "ssti": "escalate_ssti",
    "ssrf": "escalate_ssrf", "xxe": "escalate_xxe",
    "lfi": "escalate_lfi", "path_traversal": "escalate_lfi",
    "idor": "escalate_idor", "bola": "escalate_idor",
    "open_redirect": "escalate_open_redirect",
    "prototype_pollution": "escalate_prototype_pollution",
}


async def get_next_action_impl(
    target_url: str,
    completed_phases: list[str] | None = None,
    findings_count: int = 0,
    tested_params: list[str] | None = None,
    tech_stack: list[str] | None = None,
    unconfirmed_findings: list[dict] | None = None,
    confirmed_findings: list[dict] | None = None,
) -> str:
    completed = set(completed_phases or [])
    techs = tech_stack or ["default"]

    # FINDINGS-FIRST: if there are unconfirmed leads, confirm them before
    # scanning more. A lead is worth more than a new scan target.
    if unconfirmed_findings:
        for f in unconfirmed_findings:
            vtype = (f.get("vuln_type") or f.get("type") or "").lower()
            endpoint = f.get("endpoint") or f.get("url") or ""
            param = f.get("parameter") or ""
            tool = _CONFIRM_TOOLS.get(vtype)
            if tool:
                return (
                    f"NEXT: Confirm the {vtype} lead on {endpoint}.\n"
                    f"  {tool}(endpoint='{endpoint}'"
                    + (f", parameter='{param}'" if param else "")
                    + ")\n"
                    f"  This is higher priority than more scanning — a confirmed "
                    f"finding beats ten unverified anomalies."
                )
        # Generic unconfirmed leads without a specific confirm tool
        f0 = unconfirmed_findings[0]
        return (
            f"NEXT: Verify the {f0.get('vuln_type', 'unknown')} lead on "
            f"{f0.get('endpoint', '?')}.\n"
            f"  Replay 3x with resend_with_modification(index={f0.get('proxy_history_index', '?')})\n"
            f"  Compare against baseline. If confirmed → assess_finding → save_finding."
        )

    # ESCALATE confirmed findings to prove real impact before moving on.
    if confirmed_findings:
        for f in confirmed_findings:
            vtype = (f.get("vuln_type") or "").lower()
            endpoint = f.get("endpoint") or ""
            tool = _ESCALATE_TOOLS.get(vtype)
            if tool and not f.get("escalated"):
                return (
                    f"NEXT: Escalate the confirmed {vtype} on {endpoint} to "
                    f"prove real impact.\n"
                    f"  {tool}(endpoint='{endpoint}')\n"
                    f"  Impact proof: what can an attacker GAIN? "
                    f"(data dump, credential theft, RCE, account takeover)"
                )

    # Auto-scan not done yet
    if "auto_scan" not in completed:
        return (
            f"NEXT: Run the default scanners first.\n"
            f"  1. run_vigil(target='{target_url}', profile='thorough')\n"
            f"  2. run_groma(target='{target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url}')\n"
            f"  3. import_scan_results(path=<vigil output>, fmt='vigil')\n"
            f"  Then analyze results before manual testing."
        )

    if "recon" not in completed:
        return (
            f"NEXT: Fill recon gaps the auto-scan missed.\n"
            f"  browser_crawl('{target_url}', max_pages=20)\n"
            f"  smart_analyze(index=<most interesting page>)"
        )

    if "probe" not in completed:
        vulns = []
        for tech in techs:
            vulns.extend(TECH_PRIORITIES.get(tech.lower(), TECH_PRIORITIES["default"]))
        vulns = list(dict.fromkeys(vulns))[:5]
        return (
            f"NEXT: Targeted probing (classes vigil does not cover).\n"
            f"  auto_probe(session='<session>', categories={vulns[:3]})\n"
            f"  Focus: business logic, auth matrix, race conditions."
        )

    if findings_count == 0:
        return (
            "NEXT: No findings yet. Change approach:\n"
            "  1. test_auth_matrix() — highest ROI for authenticated targets\n"
            "  2. discover_common_files() → chain sensitive files into impact\n"
            "  3. fuzz_api_schema(spec_url=<OpenAPI URL>) if API spec found\n"
            "  4. propose_chains(domain) — can existing LOW findings chain into impact?"
        )

    from urllib.parse import urlparse
    parsed_host = urlparse(target_url).hostname
    if not parsed_host:
        parsed_host = target_url.split("/", 1)[0] or target_url
    return (
        f"NEXT: All phases complete with {findings_count} findings.\n"
        f"  1. Review: which have real IMPACT? Which can be chained?\n"
        f"  2. save_finding() for each confirmed finding\n"
        f"  3. generate_report('{parsed_host}')\n"
        f"  4. save_target_intel() to persist for future sessions"
    )
