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

from burpsuite_mcp.tools.advisor import _cvss4
from burpsuite_mcp.tools.advisor.assess import assess_finding_impl
from burpsuite_mcp.tools.advisor.hunt_plan import get_hunt_plan_impl
from burpsuite_mcp.tools.advisor.next_action import get_next_action_impl
from burpsuite_mcp.tools.advisor.pick_tool import TIER1_HUNT_LOOP, pick_tool_impl
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
        intensity: str = "normal",
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
            intensity: Engagement mode. 'safe' = production / customer-impact-sensitive (annotates that state-mutating probe variants should be suppressed). 'normal' = default. 'aggressive' = staging / pre-engagement / authorized internal — relaxes the Q7 mass-report downgrade.
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
        vuln_type: str,
        requires_auth: bool = False,
        requires_admin: bool = False,
        requires_interaction: bool = False,
        oob_only: bool = False,
        subsequent_impact: str = "",
        exploit_maturity: str = "X",
        env_overrides: dict | None = None,
    ) -> dict:
        """Build CVSS 4.0 + CVSS 3.1 vectors for a finding, with categorical severity band.

        Returns {cvss4_vector, cvss4_macrovector, cvss4_band, cvss31_vector,
        suggested_overrides, note}. Operator-owned: caller passes finding shape
        flags (requires_auth, requires_interaction, subsequent_impact) and any
        Threat/Environmental metric overrides via env_overrides (e.g. {"E":"A","CR":"H"}).

        Args:
            vuln_type: Vulnerability type (sqli, xss, ssrf, idor, ...). Falls
                back to info_disclosure default if unknown.
            requires_auth: True → PR:L. requires_admin → PR:H.
            requires_interaction: True → UI:A (Active victim action).
            oob_only: True → AT:P + AC:H (Attack Requirements present, complex).
            subsequent_impact: "high" → SC:H SI:H SA:H (scope change).
            exploit_maturity: CVSS 4.0 E metric — A (Attacked) / P (PoC) / U
                (Unreported) / X (Not Defined, default).
            env_overrides: optional dict of valid 4.0 metric:value (E, CR, IR,
                AR, MAV, ...). Invalid entries silently dropped.
        """
        evidence = {
            "requires_auth": requires_auth,
            "requires_admin": requires_admin,
            "requires_interaction": requires_interaction,
            "oob_only": oob_only,
            "subsequent_impact": subsequent_impact,
        }
        env = dict(env_overrides or {})
        if exploit_maturity and exploit_maturity != "X":
            env["E"] = exploit_maturity
        try:
            v4 = _cvss4.build_vector(vuln_type, evidence=evidence, env=env)
            parsed = _cvss4.parse_vector(v4)
            mv = _cvss4.macrovector(parsed)
            band = _cvss4.band_from_macrovector(mv)
            v31 = _cvss4.to_cvss31_vector(parsed)
            return {
                "cvss4_vector": v4,
                "cvss4_macrovector": mv,
                "cvss4_band": band,
                "cvss31_vector": v31,
                "note": (
                    "cvss4_band is APPROXIMATE — derived from MacroVector "
                    "equivalence classes. For exact numeric score, install "
                    "the `cvss` pip package and call cvss.CVSS4(vector).base_score."
                ),
            }
        except ValueError as exc:
            return {"error": str(exc), "vuln_type": vuln_type}

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
