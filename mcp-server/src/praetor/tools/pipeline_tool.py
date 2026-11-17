"""run_pipeline / describe_tools — server-side tool composition.

run_pipeline executes a sequence of tool calls in one MCP round trip.
The model sends one pipeline instead of N individual calls. Only the final
result enters context (or all results with return_all=True).

describe_tools returns full input schemas for multiple tools in one call —
batch lazy-loading for hosts that defer schema resolution.

Inspired by Cloudflare Code Mode: composition, looping, and result forwarding
stay server-side so intermediate outputs never inflate the model's context.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import Context, FastMCP

from praetor import _lanes, _tool_rag

_MAX_STEP_CHARS = 50_000


def _result_to_str(result: object) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, (dict, list)):
        return json.dumps(result, ensure_ascii=False, indent=None)
    return str(result)


def _substitute_refs(value: object, results: list[str]) -> object:
    """Replace $prev and $step.N references in string values, recursively."""
    if isinstance(value, str):
        if "$prev" in value and results:
            value = value.replace("$prev", results[-1])
        for m in re.finditer(r"\$step\.(\d+)", value):
            idx = int(m.group(1))
            if 0 <= idx < len(results):
                value = value.replace(m.group(0), results[idx])
        return value
    if isinstance(value, dict):
        return {k: _substitute_refs(v, results) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_refs(v, results) for v in value]
    return value


def _lookup_tool(mcp: FastMCP, name: str):
    tm = mcp._tool_manager
    return (
        tm._tools.get(name)
        or _lanes.HIDDEN.get(name)
        or _tool_rag.HIDDEN_BY_RAG.get(name)
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_pipeline(
        steps: list[dict],
        return_all: bool = False,
        stop_on_error: bool = True,
        ctx: Context = None,
    ) -> str:
        """Execute a sequence of tool calls server-side in one round trip.

        Cuts N tool calls to 1. Only the final result enters model context
        (pass return_all=True for all results). Intermediate results stay
        server-side — no context bloat from large JSON that only feeds the
        next step.

        Each step: {"tool": "<name>", "args": {<arguments>}}

        Result forwarding (string substitution in args):
          $prev  — full text of the previous step's result.
          $step.0, $step.1, ...  — result of step N (0-indexed).

        Common pipelines this replaces:
          - Recon: load_target_intel -> discover_attack_surface -> auto_probe
          - Verify: get_request_detail -> resend_with_modification -> annotate
          - Save:  assess_finding -> save_finding

        Args:
            steps: ordered list of tool calls. Each dict has 'tool' (str)
                and optional 'args' (dict). Min 1, max 20 steps.
            return_all: return every step's result, not just the last.
            stop_on_error: halt on first failure (default True).
        """
        if not steps:
            return json.dumps({"error": "empty pipeline — provide at least one step"})
        if len(steps) > 20:
            return json.dumps({"error": "max 20 steps per pipeline"})

        results: list[str] = []
        step_meta: list[dict] = []

        for i, step in enumerate(steps):
            tool_name = step.get("tool") or ""
            raw_args = step.get("args") or {}

            tool = _lookup_tool(mcp, tool_name)
            if tool is None:
                err = f"step {i}: unknown tool {tool_name!r}"
                if stop_on_error:
                    return json.dumps({
                        "error": err,
                        "completed": i,
                        "results": results if return_all else [],
                    })
                results.append(f"ERROR: {err}")
                step_meta.append({"tool": tool_name, "ok": False, "error": err})
                continue

            resolved_args = _substitute_refs(raw_args, results)
            if not isinstance(resolved_args, dict):
                resolved_args = {}

            try:
                raw_result = await tool.run(resolved_args, context=ctx)
                text = _result_to_str(raw_result)
                if len(text) > _MAX_STEP_CHARS:
                    text = text[:_MAX_STEP_CHARS] + f"\n... [truncated at {_MAX_STEP_CHARS} chars]"
                results.append(text)
                step_meta.append({"tool": tool_name, "ok": True, "chars": len(text)})
            except Exception as exc:
                err = f"step {i} ({tool_name}): {exc}"
                if stop_on_error:
                    return json.dumps({
                        "error": err,
                        "completed": i,
                        "results": results if return_all else [],
                    })
                results.append(f"ERROR: {err}")
                step_meta.append({"tool": tool_name, "ok": False, "error": str(exc)})

        if return_all:
            return json.dumps({
                "steps": step_meta,
                "results": results,
            }, ensure_ascii=False)

        return results[-1] if results else json.dumps({"error": "no results"})

    @mcp.tool()
    async def describe_tools(names: list[str]) -> str:
        """Return full input schemas for multiple tools in one call.

        Batch lazy-loading: fetch schemas for N tools in one round trip
        instead of N run_tool(name) calls. Use after pick_tool(task) or
        list_tier1_tools() identifies the tools you need.

        Args:
            names: list of tool names (max 25).
        """
        if len(names) > 25:
            return json.dumps({"error": "max 25 tools per call"})

        schemas: list[dict] = []
        for name in names:
            tool = _lookup_tool(mcp, name)
            if tool is None:
                schemas.append({"tool": name, "error": "not found"})
            else:
                schemas.append({
                    "tool": name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                })
        return json.dumps(schemas, ensure_ascii=False)


__all__ = ["register"]
