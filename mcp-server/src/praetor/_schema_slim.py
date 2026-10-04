"""Strip pydantic's auto-generated `title` keys from tool input schemas.

Pydantic emits a `"title"` for every model and every field — `{"domain": {"title":
"Domain", "type": "string"}}`. The value is the property key title-cased, so it
carries no information the client does not already have from the key itself.

Across this server's tool surface that is a meaningful slice of the tool manifest,
paid on every session before the operator has asked for anything. Removing it is
lossless: MCP treats `title` as an optional display hint, and the
JSON Schema validation semantics are unchanged.

Only `title` is removed. `description`, `default`, `enum` and every type
constraint are load-bearing and stay.
"""

from __future__ import annotations

import os
import re

# Keys whose values are maps of name -> schema. Descending into these means the
# child KEYS are names (a property may legitimately be called "title"), so the
# recursion must not treat them as schema nodes.
_SCHEMA_MAPS = ("properties", "$defs", "definitions", "patternProperties")

# Keys whose values are a single nested schema.
_SCHEMA_NODES = ("items", "additionalProperties", "not", "if", "then", "else")

# Keys whose values are lists of schemas.
_SCHEMA_LISTS = ("anyOf", "oneOf", "allOf", "prefixItems")


def strip_titles(schema: dict) -> dict:
    """Recursively drop `title` from a JSON Schema node. Mutates and returns it."""
    if not isinstance(schema, dict):
        return schema
    schema.pop("title", None)
    for key in _SCHEMA_MAPS:
        node = schema.get(key)
        if isinstance(node, dict):
            for child in node.values():
                strip_titles(child)
    for key in _SCHEMA_NODES:
        strip_titles(schema.get(key))
    for key in _SCHEMA_LISTS:
        node = schema.get(key)
        if isinstance(node, list):
            for child in node:
                strip_titles(child)
    return schema


def slim_tool_schemas(mcp) -> int:
    """Slim every registered tool's parameter schema. Returns tools touched.

    NOTE: reads FastMCP's tool registry through `_tool_manager`, which is
    private API. It is the only place the assembled schemas are reachable
    before serving. If a future SDK renames it this becomes a no-op rather than
    an error — the cost is a fatter manifest, not a broken server.
    """
    manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if not isinstance(tools, dict):
        return 0
    for tool in tools.values():
        params = getattr(tool, "parameters", None)
        if isinstance(params, dict):
            strip_titles(params)
    return len(tools)


# ------------------------------------------------------------------ descriptions
#
# Tool descriptions are ~70% of the assembled manifest. An eager-loading host
# (Codex / dsh) pays the whole thing on every request. Trimming each description
# to its one-line summary cuts the manifest by roughly 4x; the full docstring
# stays reachable on demand via pick_tool(task) / run_tool('<tool>'). Lossy, so
# it is OPT-IN: explicit PRAETOR_SLIM_DESCRIPTIONS, else auto for a lean
# (non-`all`) profile — the exact case where the host is eager and context-bound.

_FIRST_SENTENCE = re.compile(r"^(.*?[.!?])(?:\s|$)", re.S)


def first_sentence(text: str) -> str:
    """The one-line summary of a docstring: its first non-empty line, truncated
    to the first sentence when that line itself runs long (>160 chars)."""
    if not text:
        return text
    line = ""
    for ln in text.strip().splitlines():
        if ln.strip():
            line = ln.strip()
            break
    if len(line) <= 160:
        return line
    m = _FIRST_SENTENCE.match(line)
    return m.group(1) if m else line[:157] + "…"


def should_slim_descriptions() -> bool:
    """True when the manifest's descriptions should be trimmed to summaries.

    PRAETOR_SLIM_DESCRIPTIONS wins (1/true/yes/on or 0/false/no/off); otherwise
    auto-on for any lean profile (PRAETOR_PROFILE set and not `all`), the eager,
    context-bound case. Default (no profile, no flag) = off (Claude Code).
    """
    v = os.environ.get("PRAETOR_SLIM_DESCRIPTIONS", "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    prof = (os.environ.get("PRAETOR_PROFILE") or "").strip().lower()
    return bool(prof) and prof != "all"


def slim_descriptions(mcp, enabled: bool | None = None) -> int:
    """Trim each registered tool's description to its one-line summary. Returns
    the number trimmed (0 when disabled or registry unreachable). Full guidance
    stays available through pick_tool / run_tool, so nothing is lost permanently.
    """
    if enabled is None:
        enabled = should_slim_descriptions()
    if not enabled:
        return 0
    manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if not isinstance(tools, dict):
        return 0
    n = 0
    for tool in tools.values():
        d = getattr(tool, "description", None)
        if isinstance(d, str) and d:
            s = first_sentence(d)
            if s and s != d:
                try:
                    tool.description = s
                    n += 1
                except (AttributeError, TypeError, ValueError):
                    pass
    return n
