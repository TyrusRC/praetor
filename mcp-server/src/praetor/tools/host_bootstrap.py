"""Session-start bridge for a Tools-only MCP host (dsh, Codex, ...).

Claude Code auto-loads CLAUDE.md, the rule files, the skill library and the
agent roster from disk. A host that bridges only MCP TOOLS — no resource
support, no file auto-load — gets none of that for free, so it must fetch them.

`praetor_bootstrap` is the single call that tells such a host how to run Praetor
like Claude Code, and `get_rules` exposes the always-active rule files as a TOOL
(before this they were reachable only through the `burp://rules/*` resources,
invisible to a tools-only host).

The HARD safety rules (5-9) and the 7-gate save-finding pipeline are enforced in
the tool layer, so they apply on every host regardless of what is loaded here —
these tools hand over the WORKFLOW, not the enforcement.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

# mcp-server/src/praetor/tools/host_bootstrap.py -> parents[4] == repo root
RULES_DIR = Path(__file__).resolve().parents[4] / ".claude" / "rules"

_RULES = ("hunting", "engineering")


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def get_rules(name: str = "hunting") -> dict:
        """Load an always-active rule file as a TOOL.

        Claude Code auto-loads these; a tools-only host cannot read the
        `burp://rules/*` resources, so it fetches them here.

        Args:
            name: 'hunting' (scope / safety / evidence / coverage / save-finding
                  pipeline) or 'engineering' (think-first, simplicity, surgical,
                  goal-driven).
        """
        if name not in _RULES:
            return {"error": f"unknown rules {name!r}", "available": list(_RULES)}
        path = RULES_DIR / f"{name}.md"
        if not path.exists():
            return {"error": f"{name}.md not found under {RULES_DIR}"}
        return {"name": name, "markdown": path.read_text(encoding="utf-8")}

    @mcp.tool()
    async def praetor_bootstrap() -> dict:
        """Session-start onboarding for a non-Claude MCP host. CALL THIS FIRST.

        Hands a tools-only host (dsh / Codex) the same operating context Claude
        Code gets from auto-loaded files: which rules to load, the web/network/
        mobile flows, and the save-finding pipeline. Safety Rules 5-9 and the
        7-gate finding pipeline are enforced in the tool layer and apply on every
        host regardless — this returns the WORKFLOW, not the enforcement.
        """
        return {
            "load_first": [
                "get_rules('hunting')      — HARD scope/safety + evidence/coverage/save-finding rules",
                "get_rules('engineering')  — how to work (think-first, surgical, goal-driven)",
                "list_skills() / get_skill(name)  — procedural playbooks (HOW to do a task)",
                "list_agents() / get_agent(name)  — strategy playbooks behind the team",
                "list_tier1_tools() / pick_tool(task)  — find the right tool for a task",
            ],
            "web_hunt_loop": [
                "load_target_intel(domain, 'all') + check_target_freshness(domain, session)  — Rule 20a recon gate, FIRST",
                "discover_attack_surface(domain)  — pre-scoped attack surface",
                "auto_probe(...)  — knowledge-base-driven vuln sweep",
                "get_next_action(domain) / get_hunt_plan(domain)  — sequential orchestration (replaces subagent dispatch)",
            ],
            "network_lane": [
                "run_network_recon(target)  — discover -> service enum -> leads -> auto-loot -> web-lane bridge",
                "run_nmap / run_httpx / run_nuclei / run_ffuf / run_subfinder / run_network_tool(...)  — external CLIs, all driven through Praetor",
                "network actions bypass Burp and cite an operator-log id, not a proxy index",
            ],
            "mobile_lane": [
                "mobile_devices() -> mobile_connect(...) -> mobile_set_proxy(...) -> mobile_frida_run(...)",
                "adb/frida run on the host where THIS server runs; the phone attaches there",
            ],
            "save_finding_pipeline": [
                "verify (replay >= 3x) -> assess_finding(7-gate) -> save_finding",
                "tool-layer enforced: a finding failing scope/dedup/evidence/impact is rejected regardless of host",
            ],
            "note": (
                "Everything Claude Code does via auto-loaded files, a tools-only host does via "
                "these tools. The one thing it cannot replicate is PARALLEL multi-agent execution; "
                "the orchestration tools (get_hunt_plan / get_next_action / route_signals / "
                "judge_completion) give the single-threaded equivalent."
            ),
        }
