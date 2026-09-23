"""Non-blocking tool-lane control — run or promote gated tools at runtime.

Profile gating (`_lanes`) hides tools from the manifest to save context on an
eager-loading host, but a gated tool is never a dead end: it stays executable.

- `run_tool(name, args)` runs ANY tool, gated or not — and `run_tool(name)` with no
  args returns its input schema first. That is app-layer lazy tool loading: the exact
  capability dsh's MCP client lacks (it eager-loads everything and cannot defer), now
  provided by one always-present core tool.
- `use_lane(lane)` re-advertises a whole lane.

Both fire `tools/list_changed` so a host that honours it (Claude Code) shows promoted
tools live; on dsh (which ignores it) `run_tool` still reaches everything, so a
workflow is never blocked. These two tools are CORE — always advertised — so the
escape hatch is always in the manifest.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from praetor import _lanes


async def _notify(ctx: Context | None) -> None:
    """Best-effort tools/list_changed. Harmless where the host ignores it."""
    if ctx is None:
        return
    try:
        await ctx.session.send_tool_list_changed()
    except Exception:
        pass


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def run_tool(name: str, arguments: dict | None = None,
                       promote: bool = True, ctx: Context = None) -> dict:
        """Run any tool the active PROFILE has gated out of the manifest — never blocked.

        Gating hides tools to save context; this reaches any of them. Call
        `run_tool(name)` with NO arguments to fetch the tool's input schema, then
        `run_tool(name, {args})` to execute it. After a gated tool runs, its whole lane
        is promoted (re-advertised) by default so later calls are direct. Find gated
        tool names via `pick_tool(task)`, `list_tier1_tools()`, `list_knowledge()`, or
        `get_profile()`.

        Args:
            name: the tool to run (gated or already-advertised).
            arguments: the tool's args as an object. Omit (null) to fetch its schema
                instead of running.
            promote: after a successful run of a gated tool, re-advertise its lane
                (default True).
        """
        tm = mcp._tool_manager
        tool = tm._tools.get(name) or _lanes.HIDDEN.get(name)
        if tool is None:
            return {"error": f"unknown tool {name!r}",
                    "hint": "find the right tool with pick_tool(task) or list_tier1_tools()."}
        hidden = name in _lanes.HIDDEN
        lane = _lanes._lane_of(name, tool)
        if arguments is None:
            return {"tool": name, "lane": lane, "gated": hidden,
                    "input_schema": tool.parameters, "description": tool.description,
                    "hint": f"execute with run_tool({name!r}, {{...args...}})."}
        result = await tool.run(arguments, context=ctx)
        promoted: list[str] = []
        if hidden and promote:
            promoted = _lanes.promote_lane(mcp, lane)
            if promoted:
                await _notify(ctx)
        return {"tool": name, "lane": lane, "result": result,
                "lane_promoted": bool(promoted)}

    @mcp.tool()
    async def use_lane(lane: str, ctx: Context = None) -> dict:
        """Re-advertise a gated tool lane so its tools appear directly in the manifest.

        Optional convenience — `run_tool` already reaches gated tools without this. On a
        host that honours tools/list_changed (Claude Code) the lane appears live; on dsh
        it will not surface until reconnect, but run_tool still works. To NARROW the set,
        edit `PRAETOR_PROFILE` in the server config and reconnect.

        Args:
            lane: one of get_profile()['all_lanes'] (web / network / mobile / llm / ...).
        """
        if lane not in _lanes.ALL_LANES:
            return {"error": f"unknown lane {lane!r}", "lanes": list(_lanes.LANES)}
        promoted = _lanes.promote_lane(mcp, lane)
        if promoted:
            await _notify(ctx)
        return {"lane": lane, "promoted": len(promoted), "tools": promoted,
                "note": "run_tool reached these already; promotion just re-advertises them."}
