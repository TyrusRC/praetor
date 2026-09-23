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
REPO_ROOT = Path(__file__).resolve().parents[4]
RULES_DIR = REPO_ROOT / ".claude" / "rules"

# name -> path. 'project' is the checked-in project CLAUDE.md (repo root), NOT
# the operator's personal ~/.claude/CLAUDE.md — only the in-repo file is served.
_RULE_PATHS = {
    "hunting": RULES_DIR / "hunting.md",
    "engineering": RULES_DIR / "engineering.md",
    "project": REPO_ROOT / "CLAUDE.md",
}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def get_rules(name: str = "hunting") -> dict:
        """Load an always-active rule / project-guideline file as a TOOL.

        Claude Code auto-loads all of these from disk; a tools-only host cannot
        read the `burp://rules/*` resources and never sees CLAUDE.md, so it
        fetches them here.

        Args:
            name: 'hunting' (scope / safety / evidence / coverage / save-finding
                  pipeline), 'engineering' (think-first, simplicity, surgical,
                  goal-driven), or 'project' (the checked-in project CLAUDE.md —
                  save-finding gates, override surfaces, output discipline, Burp
                  editions; the behavioural spec Claude Code loads natively).
        """
        path = _RULE_PATHS.get(name)
        if path is None:
            return {"error": f"unknown rules {name!r}", "available": list(_RULE_PATHS)}
        if not path.exists():
            return {"error": f"{name} file not found at {path}"}
        return {"name": name, "markdown": path.read_text(encoding="utf-8")}

    @mcp.tool()
    async def get_profile() -> dict:
        """Report the active tool PROFILE and how to change it.

        Praetor can advertise only the tool lanes an engagement needs, to shrink the
        manifest an eager-loading host (dsh / Codex via the API) sends to the model.
        The starting profile is set by the `PRAETOR_PROFILE` env var. A gated tool is
        never blocked: run_tool runs it and promotes its lane, firing tools/list_changed
        so the host re-fetches and the lane appears live (Claude Code and the dsh client
        both honour it). Claude Code also defers tool schemas, so it pays little either
        way.
        """
        from praetor import _lanes
        live = _lanes.LAST_APPLIED
        hidden = _lanes.hidden_by_lane()
        return {
            "active_profile": live["profile"],
            "enabled_lanes": live["enabled_lanes"],
            "tools_advertised": live["kept"],
            "tools_gated_out": live["removed"],
            "gated_lanes": {lane: len(names) for lane, names in sorted(hidden.items())},
            "all_lanes": list(_lanes.LANES),
            "named_profiles": sorted(_lanes.PROFILES),
            "mid_engagement_pivot": (
                "Need a gated tool (e.g. pivot from web to mobile/network/cloud)? It is "
                "NEVER blocked: run_tool('<tool>', {args}) executes it and auto-enables "
                "its lane; run_tool('<tool>') returns its schema; use_lane('<lane>') "
                "re-advertises the whole lane. pick_tool(task) flags gated tools for you."
            ),
            "change_it": (
                "To set the STARTING profile, set env PRAETOR_PROFILE in the MCP server "
                "config (e.g. dsh cordis.yml env: { PRAETOR_PROFILE: 'web' }) then "
                "reconnect. Values: a named profile (web/network/mobile/llm/cloud/core/"
                "all/...) or a comma list of lanes (web,network). Core is always on."
            ),
            "note": (
                "Safety Rules 5-9 and the 7-gate save-finding pipeline are enforced in "
                "the tool layer and unaffected by the profile."
            ),
        }

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
                "get_rules('project')      — project CLAUDE.md: save-finding gates, override surfaces, output discipline (Claude Code auto-loads this; you must fetch it)",
                "list_skills() / get_skill(name)  — procedural playbooks (HOW to do a task)",
                "list_prompts() / get_prompt(name, args)  — one-call workflow launchers (hunt-target, triage-program, save-finding-checklist, ...)",
                "list_agents() / get_agent(name)  — strategy playbooks behind the team",
                "list_knowledge() / get_knowledge(category)  — probe-class KB (matchers + craft guidance) auto_probe consumes",
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
            "profile_and_pivot": [
                "get_profile()  — which tool lanes are advertised vs gated (context-saving on eager hosts)",
                "a gated tool is NEVER blocked: run_tool('<tool>', {args}) runs it + auto-enables its lane; run_tool('<tool>') returns its schema",
                "mid-engagement pivot (web -> mobile/network/cloud) just works via run_tool; pick_tool(task) flags gated tools",
            ],
            "model_tiers": [
                "Agent playbooks are pinned to Claude tiers (opus / sonnet / haiku). On a non-Claude host, map the generic `tier` in list_agents to YOUR platform's nearest model:",
                "  strategic (opus)  -> your strongest reasoning model — commanders + hard 'what next and why' decisions (hunting Rule 33)",
                "  standard  (sonnet) -> your balanced default model — most workers",
                "  fast      (haiku)  -> your cheapest/fastest model — bulk, low-stakes steps",
                "If your host has only one model, run everything on it; the escalation in Rule 33 becomes a no-op, not a blocker.",
            ],
            "note": (
                "Everything Claude Code does via auto-loaded files, a tools-only host does via "
                "these tools. The one thing it cannot replicate is PARALLEL multi-agent execution; "
                "the orchestration tools (get_hunt_plan / get_next_action / route_signals / "
                "judge_completion) give the single-threaded equivalent."
            ),
        }
