"""Strip pydantic's auto-generated `title` keys from tool input schemas.

Pydantic emits a `"title"` for every model and every field — `{"domain": {"title":
"Domain", "type": "string"}}`. The value is the property key title-cased, so it
carries no information the client does not already have from the key itself.

Across this server's tool surface that is ~34 KB (~9k tokens) of the tool
manifest, paid on every session before the operator has asked for anything.
Removing it is lossless: MCP treats `title` as an optional display hint, and the
JSON Schema validation semantics are unchanged.

Only `title` is removed. `description`, `default`, `enum` and every type
constraint are load-bearing and stay.
"""

from __future__ import annotations

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
