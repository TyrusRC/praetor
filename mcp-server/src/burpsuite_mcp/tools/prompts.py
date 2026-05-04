"""MCP Prompts surface — operator-invokable workflow templates.

Prompts give the user concrete launchers for the most common engagement
phases without having to remember which tool calls to chain. Each prompt
returns a fully-formed instruction the LLM can execute against the live
session.
"""

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP):

    @mcp.prompt("hunt-target")
    def hunt_target(target: str = "https://example.com") -> str:
        """Run the standard hunt loop on a target — recon, probe, verify, save."""
        return (
            f"Run a complete authorized hunt against {target}. Steps:\n"
            f"1. configure_scope to include {target} and auto-filter trackers/CDNs.\n"
            f"2. get_hunt_plan({target!r}) to load the phased plan.\n"
            f"3. browser_crawl({target!r}) to populate Burp proxy history.\n"
            f"4. discover_attack_surface to map endpoints and risk-score parameters.\n"
            f"5. auto_probe with skip_already_covered=True against discovered targets.\n"
            f"6. For each anomaly: replay 3x, assess_finding, save_finding when REPORT.\n"
            f"7. chain-findings on low-severity items before generating the final report.\n"
            f"Honor every rule in .claude/rules/hunting.md. Do not exit early."
        )

    @mcp.prompt("verify-finding")
    def verify_finding_prompt(
        vuln_type: str = "sqli",
        endpoint: str = "/path?param=value",
        evidence: str = "describe what you observed",
    ) -> str:
        """Walk a suspected finding through the 7-Question Validation Gate."""
        return (
            f"Verify a suspected {vuln_type} on {endpoint}.\n"
            f"Operator notes: {evidence}\n\n"
            "Procedure:\n"
            "1. Resend the captured request 3x via resend_with_modification — capture {logger_index, elapsed_ms, status_code} per replay.\n"
            "2. Confirm anomaly persists vs baseline (status / length / hash / timing).\n"
            "3. Match the per-class evidence bar in .claude/skills/verify-finding.md.\n"
            f"4. Call assess_finding(vuln_type={vuln_type!r}, endpoint={endpoint!r}, evidence={{...}}, reproductions=[...]).\n"
            "5. If verdict is REPORT: save_finding with the same evidence.\n"
            "6. If NEEDS MORE EVIDENCE / DO NOT REPORT: print the issues[] list and stop — do NOT save."
        )

    @mcp.prompt("triage-program")
    def triage_program(program: str = "hackerone-acme") -> str:
        """Set up per-program policy + scope + override defaults for an engagement."""
        return (
            f"Configure the engagement for program={program!r}.\n"
            "1. set_program_policy with confidence_floor / never_submit_remove / never_submit_add per program rules.\n"
            "2. configure_scope with the program's in-scope assets and keep_in_scope for any whitelisted CDN/OAuth/asset host.\n"
            "3. save_target_intel for each in-scope domain with the engagement notes.\n"
            "4. Print the active policy so the operator can confirm before testing begins."
        )

    @mcp.prompt("chain-findings")
    def chain_findings(domain: str = "example.com") -> str:
        """Walk saved findings and propose chains that escalate impact."""
        return (
            f"Build exploit chains from saved findings on {domain}.\n"
            "1. load_target_intel(domain, 'findings') to fetch the current finding list.\n"
            "2. For each NEVER-SUBMIT-class finding (open redirect, info disclosure, CSRF on logout): identify a partner finding that yields ATO / token theft / data exposure when combined.\n"
            "3. Use chain-findings.md mapping table.\n"
            "4. For each viable chain: assess_finding with chain_with=[<partner_id>] and overrides=['q6_never_submit:chained-with-<id>:<rationale>'].\n"
            "5. save_finding for the chain with chain_with[] populated."
        )

    @mcp.prompt("save-finding-checklist")
    def save_finding_checklist(
        vuln_type: str = "sqli",
        endpoint: str = "/api/v1/users/123",
    ) -> str:
        """Pre-save checklist enforcing the three-phase save pipeline."""
        return (
            f"Pre-save checklist for {vuln_type} on {endpoint}:\n\n"
            "Phase 1 — REPLAY (Rule 10a):\n"
            "  [ ] resend_with_modification(index) confirmed the anomaly\n"
            "  [ ] For timing/blind: 3+ replays captured into reproductions[{logger_index, elapsed_ms, status_code}]\n\n"
            "Phase 2 — ASSESS (Rule 10b):\n"
            "  [ ] assess_finding called with full evidence dict + endpoint + parameter + domain\n"
            "  [ ] Verdict is REPORT (not NEEDS MORE EVIDENCE / DO NOT REPORT)\n"
            "  [ ] If NEVER-SUBMIT class: chain_with[] populated\n\n"
            "Phase 3 — SAVE (Rule 10c):\n"
            "  [ ] evidence has at least one of logger_index / proxy_history_index / collaborator_interaction_id\n"
            "  [ ] Severity locked by operator (not advisor's suggestion if they disagree)\n"
            "  [ ] domain set so the finding lands in .burp-intel/<domain>/findings.json\n"
            "Run save_finding once every box is checked. Tool layer hard-rejects on Phase 3 violations."
        )
