"""Cross-host prompt access — the MCP Prompt templates as TOOLS.

Praetor's workflow launchers (hunt-target, verify-finding, triage-program,
chain-findings, save-finding-checklist) are registered via the MCP *Prompts*
primitive in `prompts.py`. Several non-Claude hosts (dsh, Codex) bridge only
MCP Tools and defer Prompts, so those launchers are invisible there.

`list_prompts` / `get_prompt` expose the same templates as tools. Two of them
— triage-program and save-finding-checklist — have no skill equivalent, so
without this bridge a Tools-only host loses them entirely. Mirrors
skills_access / agents_access.
"""

from __future__ import annotations

import inspect

from mcp.server.fastmcp import FastMCP

from .prompts import PROMPTS


def _params(fn) -> list[dict]:
    """Each builder arg as {name, default}."""
    out = []
    for name, p in inspect.signature(fn).parameters.items():
        default = "" if p.default is inspect.Parameter.empty else p.default
        out.append({"name": name, "default": default})
    return out


def prompt_entries() -> list[dict]:
    """Pure: every prompt's {name, description, args}, sorted by name."""
    out = []
    for name, fn in sorted(PROMPTS.items()):
        out.append({
            "name": name,
            "description": (inspect.getdoc(fn) or "").split("\n", 1)[0],
            "args": _params(fn),
        })
    return out


def render_prompt(name: str, args: dict | None = None) -> dict:
    """Pure: {name, args, text} for one rendered prompt, or {error, available}."""
    fn = PROMPTS.get(name)
    if fn is None:
        return {"error": f"prompt {name!r} not found", "available": sorted(PROMPTS)}
    allowed = set(inspect.signature(fn).parameters)
    supplied = {k: v for k, v in (args or {}).items() if k in allowed}
    return {"name": name, "args": supplied, "text": fn(**supplied)}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def list_prompts() -> dict:
        """List Praetor's workflow-launcher templates — the MCP Prompts, as a tool.

        Each entry is a fully-formed instruction that chains the right tools for a
        common phase (hunt-target, verify-finding, triage-program, chain-findings,
        save-finding-checklist). Claude Code / any host with MCP-Prompts support
        surfaces these natively; a Tools-only host (dsh / Codex) reaches them here.
        Render one with `get_prompt(name, args)`. Returns each template's name,
        one-line description, and its args with defaults.
        """
        entries = prompt_entries()
        return {"count": len(entries), "prompts": entries}

    @mcp.tool()
    async def get_prompt(name: str, args: dict | None = None) -> dict:
        """Render one workflow-launcher template by name, filling its args.

        Call `list_prompts()` first for names and their args. Unknown args are
        ignored; omitted args use the template default. Returns {name, args, text}
        or {error, available}.

        Args:
            name: template name, e.g. 'hunt-target', 'save-finding-checklist'.
            args: optional {arg: value} overrides, e.g. {"target": "https://x.com"}.
        """
        return render_prompt(name, args)
