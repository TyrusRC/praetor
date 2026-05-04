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

from burpsuite_mcp.tools.advisor.assess import assess_finding_impl
from burpsuite_mcp.tools.advisor.hunt_plan import get_hunt_plan_impl
from burpsuite_mcp.tools.advisor.next_action import get_next_action_impl
from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl
from burpsuite_mcp.tools.advisor.recon_phase import run_recon_phase_impl


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
    ) -> str:
        """Assess a suspected finding against the 7-Question Validation Gate before save_finding.

        Args:
            vuln_type: Vulnerability type (e.g. 'xss', 'sqli', 'idor', 'ssrf')
            evidence: What you observed (free-text)
            endpoint: The endpoint tested
            parameter: The parameter tested
            response_diff: How the response differed from baseline
            domain: Target domain for scope + duplicate checks
            business_context: Target business type for impact scoring (e.g. 'ecommerce', 'healthcare', 'banking', 'saas', 'social', 'government')
            environment: Deployment environment (e.g. 'production', 'staging', 'internal', 'public_api')
            logger_index: Proxy-history index of the confirming response. When provided, evidence is auto-augmented with class-specific markers detected programmatically (R1).
            human_verified: Operator manually confirmed in Burp UI / browser. Skips Q5 evidence gate; Q1/Q4/Q6 still apply (R19).
            overrides: Gate names to bypass (R20). Each entry "<gate>:<reason>". Recognized gates: q1_scope, q2_repro, q4_dedup, q5_evidence, q6_never_submit, q7_triager.
            chain_with: Existing finding IDs this report chains to. Non-empty list (a) allows NEVER-SUBMIT classes through Q6, (b) skips Q7 mass-report downgrade, (c) boosts impact.
            reproductions: For timing/blind classes — list of dicts {logger_index, elapsed_ms, status_code}. Length >= 3 satisfies the timing rule even without keyword text in `evidence`.
            session_name: Active session name. When provided, the gate queries session auth state; authenticated sessions boost IDOR/BFLA/business-logic impact (Rule 28 grey-box mindset).
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
        )

    @mcp.tool()
    async def pick_tool(task: str) -> str:
        """Given a task description, return the best MCP tool with example arguments.

        Args:
            task: What you want to accomplish
        """
        return await pick_tool_impl(task)
