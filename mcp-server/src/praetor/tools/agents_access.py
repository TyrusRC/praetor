"""Cross-host agent-playbook access — the `.claude/agents/*.md` roster as TOOLS.

Claude Code dispatches these as native, parallel subagents (its `Agent` tool). A
Tools-only MCP host (dsh, Codex) has no subagent dispatch, but it can still READ
each playbook — the commander / grow-agent / worker strategies — and follow it
inline in a single-threaded flow, using the orchestration tools
(get_hunt_plan / get_next_action / route_signals / judge_completion) as the
sequential equivalent of dispatch.

Exposing the roster as TOOLS (not only `burp://` resources) is what lets a
resource-less host reach it. Mirrors skills_access.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# mcp-server/src/praetor/tools/agents_access.py -> parents[4] == repo root
AGENTS_DIR = Path(__file__).resolve().parents[4] / ".claude" / "agents"

_DESC = re.compile(r"^description:\s*(.+)$", re.MULTILINE)
_MODEL = re.compile(r"^model:\s*(.+)$", re.MULTILINE)


def _field(text: str, rx: re.Pattern) -> str:
    m = rx.search(text)
    return m.group(1).strip() if m else ""


def agent_entries() -> list[dict]:
    """Pure: every agent's {name, description, model}, sorted. [] if no dir."""
    if not AGENTS_DIR.exists():
        return []
    out = []
    for p in sorted(AGENTS_DIR.glob("*.md")):
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            text = ""
        out.append({
            "name": p.stem,
            "description": _field(text, _DESC),
            "model": _field(text, _MODEL),
        })
    return out


def read_agent(name: str) -> dict:
    """Pure: {name, markdown} for one agent, or {error, available}. Traversal-safe."""
    if not name or "/" in name or "\\" in name:
        return {"error": "invalid agent name"}
    path = (AGENTS_DIR / f"{name}.md").resolve()
    try:
        path.relative_to(AGENTS_DIR.resolve())
    except ValueError:
        return {"error": "invalid agent name"}
    if not path.exists():
        return {"error": f"agent {name!r} not found",
                "available": [e["name"] for e in agent_entries()]}
    return {"name": name, "markdown": path.read_text(encoding="utf-8")}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def list_agents() -> dict:
        """List Praetor's agent roster — the strategy playbooks behind the team.

        Claude Code dispatches these as parallel subagents; a Tools-only host
        (dsh / Codex) can't dispatch them but CAN read each playbook and follow it
        inline, driving the flow with the orchestration tools (get_hunt_plan /
        get_next_action / route_signals / judge_completion) instead of parallel
        dispatch. Returns each agent's name, one-line description, and pinned
        model. Load a full playbook with `get_agent(name)`.
        """
        entries = agent_entries()
        if not entries:
            return {"count": 0, "agents": [], "note": f"no agents found under {AGENTS_DIR}"}
        return {"count": len(entries), "agents": entries}

    @mcp.tool()
    async def get_agent(name: str) -> dict:
        """Load one agent's full playbook markdown by name (file stem, no `.md`).

        Call `list_agents()` first for the available names. Returns
        {name, markdown} or {error, available}.

        Args:
            name: agent file stem, e.g. 'pentest-commander', 'recon-agent'.
        """
        return read_agent(name)
