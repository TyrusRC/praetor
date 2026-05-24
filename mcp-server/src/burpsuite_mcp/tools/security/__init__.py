"""Praetor security middleware — prompt-injection guardrail, payload sanity checks.

Defensive layer that runs in-process BEFORE outbound MCP tool calls hit the
target. CAI ships a similar declarative guardrail (prompt-injection defense +
dangerous-command blocking). Praetor's variant is operator-tunable via
set_program_policy(prompt_injection_filter='strict'|'normal'|'off').
"""

from mcp.server.fastmcp import FastMCP

from . import prompt_injection_guardrail


def register(mcp: FastMCP) -> None:
    prompt_injection_guardrail.register(mcp)
