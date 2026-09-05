"""Strategic hunt advisor — pre-computes testing plans to minimize Claude's reasoning tokens.

Implements the Advisor Strategy: instead of Claude spending tokens figuring out
WHAT to test and in WHAT order, the advisor encodes expert methodology directly
and returns structured action plans. Claude focuses on EXECUTING, not deciding.

Decision logic sourced from: hunt.md, burp-workflow.md, verify-finding.md skills.

Submodules:
    _constants     — TECH_PRIORITIES, PARAM_VULN_MAP, PHASES tables
    _helpers       — detect_tech_from_headers, prioritize_params, vuln_root
    hunt_plan      — get_hunt_plan implementation
    next_action    — get_next_action implementation
    recon_phase    — run_recon_phase implementation
    assess         — assess_finding (7-Question Validation Gate)
    pick_tool      — keyword -> MCP tool resolver
"""

from mcp.server.fastmcp import FastMCP

from praetor.tools.advisor import _cvss4
from praetor.tools.advisor.assess import assess_finding_impl
from praetor.tools.advisor.hunt_plan import get_hunt_plan_impl
from praetor.tools.advisor.next_action import get_next_action_impl
from praetor.tools.advisor.pick_tool import TIER1_HUNT_LOOP, pick_tool_impl
from praetor.tools.advisor.recon_phase import run_recon_phase_impl
from praetor.tools.advisor._scoring import (
    compute_cvss_impl, validate_severity_impl, debate_triage_impl,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_hunt_plan(
        target_url: str,
        tech_stack: list[str] | None = None,
        known_endpoints: list[str] | None = None,
    ) -> str:
        """Get a prioritized testing plan for a target with phased tool recommendations based on tech stack.

        Args:
            target_url: Target base URL
            tech_stack: Known technologies (auto-detected if omitted)
            known_endpoints: Already-discovered endpoints to skip
        """
        return await get_hunt_plan_impl(target_url, tech_stack, known_endpoints)

    @mcp.tool()
    async def get_next_action(
        target_url: str,
        completed_phases: list[str] | None = None,
        findings_count: int = 0,
        tested_params: list[str] | None = None,
        tech_stack: list[str] | None = None,
    ) -> str:
        """Get the single best next action based on current progress. Returns one specific tool call to execute.

        Args:
            target_url: Target base URL
            completed_phases: Phases done ('recon', 'probe', 'exploit', 'verify')
            findings_count: Number of findings so far
            tested_params: Parameters already tested
            tech_stack: Detected technologies
        """
        return await get_next_action_impl(
            target_url, completed_phases, findings_count, tested_params, tech_stack
        )

    @mcp.tool()
    async def run_recon_phase(
        target_url: str,
        session_name: str = "hunt",
        crawl_depth: int = 20,
    ) -> str:
        """Execute the entire recon phase in one call -- session create, tech detect, sensitive files, and analysis.

        Args:
            target_url: Target URL to recon
            session_name: Session name to create (default 'hunt')
            crawl_depth: Max pages to crawl (default 20)
        """
        return await run_recon_phase_impl(target_url, session_name, crawl_depth)

    @mcp.tool()
    async def assess_finding(
        vuln_type: str,
        evidence: str,
        endpoint: str,
        parameter: str = "",
        response_diff: str = "",
        domain: str = "",
        business_context: str = "",
        environment: str = "",
        logger_index: int = -1,
        human_verified: bool = False,
        overrides: list[str] | None = None,
        chain_with: list[str] | None = None,
        reproductions: list[dict] | None = None,
        session_name: str = "",
        intensity: str = "normal",
    ) -> str:
        """Assess a suspected finding against the 7-Question Validation Gate before save_finding.

        Args:
            vuln_type: Vuln class (e.g. 'xss', 'sqli', 'idor', 'ssrf').
            evidence: What you observed (free-text).
            endpoint: Endpoint tested.
            parameter: Parameter tested.
            response_diff: How the response differed from baseline.
            domain: Target domain (scope + duplicate checks).
            business_context: Business type for impact scoring (ecommerce/healthcare/banking/saas/...).
            environment: Deployment env (production/staging/internal/public_api).
            logger_index: Proxy index of the confirming response; auto-augments evidence with class markers.
            human_verified: Operator confirmed in Burp/browser. Skips Q5; Q1/Q4/Q6 still apply.
            overrides: Gate bypasses (R20), each "<gate>:<reason>". Gates: q1_scope/q2_repro/q4_dedup/q5_evidence/q6_never_submit/q7_triager.
            chain_with: Finding IDs to chain — allows NEVER-SUBMIT through Q6, skips Q7, boosts impact.
            reproductions: Timing/blind classes — list of {logger_index, elapsed_ms, status_code}; len>=3 satisfies the timing rule.
            session_name: Active session; authenticated state boosts IDOR/BFLA/business-logic impact.
            intensity: safe | normal | aggressive — aggressive relaxes the Q7 mass-report downgrade.
        """
        return await assess_finding_impl(
            vuln_type=vuln_type,
            evidence=evidence,
            endpoint=endpoint,
            parameter=parameter,
            response_diff=response_diff,
            domain=domain,
            business_context=business_context,
            environment=environment,
            logger_index=logger_index,
            human_verified=human_verified,
            overrides=overrides,
            chain_with=chain_with,
            reproductions=reproductions,
            session_name=session_name,
            intensity=intensity,
        )

    @mcp.tool()
    async def compute_cvss(
        vuln_type: str, requires_auth: bool = False, requires_admin: bool = False,
        requires_interaction: bool = False, oob_only: bool = False,
        subsequent_impact: str = "", exploit_maturity: str = "X",
        env_overrides: dict | None = None,
    ) -> dict:
        """Build CVSS 4.0 + 3.1 vectors + categorical band for a finding. See advisor/_scoring."""
        return await compute_cvss_impl(vuln_type, requires_auth, requires_admin,
            requires_interaction, oob_only, subsequent_impact, exploit_maturity, env_overrides)

    @mcp.tool()
    async def validate_severity(
        vuln_type: str, claimed_severity: str, requires_auth: bool = False,
        requires_admin: bool = False, requires_interaction: bool = False,
        oob_only: bool = False, subsequent_impact: str = "",
    ) -> dict:
        """Reconcile a claimed severity against the CVSS 4.0 band (Rule 14). See advisor/_scoring."""
        return await validate_severity_impl(vuln_type, claimed_severity, requires_auth,
            requires_admin, requires_interaction, oob_only, subsequent_impact)

    @mcp.tool()
    async def debate_triage(
        vuln_type: str, evidence_summary: str = "", has_chain: bool = False,
    ) -> dict:
        """Red/Blue/Judge adversarial triage scaffold before assess_finding. See advisor/_scoring."""
        return await debate_triage_impl(vuln_type, evidence_summary, has_chain)

    @mcp.tool()
    async def pick_tool(task: str) -> str:
        """Given a task description, return the best MCP tool with example arguments.

        Args:
            task: What you want to accomplish
        """
        return await pick_tool_impl(task)

    @mcp.tool()
    async def list_tier1_tools() -> dict:
        """Return the Tier-1 hunt-loop entry points (W22-d).

        Praetor exposes 300+ MCP tools; Tier-1 is the ~22 tools an operator
        should reach for first on any new target. Use this when uncertain
        which tool to pick. The full surface remains available via direct
        invocation or ToolSearch — Tier-1 is a hint, not a restriction.

        Returns:
            {"tier": 1, "count": N, "tools": [{"name": ..., "purpose": ...}, ...]}
        """
        return {
            "tier": 1,
            "count": len(TIER1_HUNT_LOOP),
            "tools": [{"name": n, "purpose": d} for n, d in TIER1_HUNT_LOOP],
            "default_chain": [
                "load_target_intel(domain)",
                "discover_attack_surface(url)",
                "auto_probe(session, categories=[...])",
                "save_finding(...) -> assess_finding(...) gate",
            ],
            "note": (
                "Full surface (300+ tools) accessible via direct call or ToolSearch. "
                "Tier-1 is a HINT — defer to specialised tools when the task matches."
            ),
        }
