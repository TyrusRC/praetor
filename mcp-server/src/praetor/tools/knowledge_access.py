"""Cross-host knowledge-base access — the probe-class categories as TOOLS.

The knowledge base under `praetor/knowledge/*.json` (probe classes + their
matchers + craft guidance) is exposed as the `burp://knowledge/*` MCP Resources,
but a Tools-only host (dsh / Codex) cannot read resources. `list_knowledge` /
`get_knowledge` give the same content as tools so any host can inspect a class
before pointing `auto_probe(categories=[...])` at it. Mirrors skills_access.

`auto_probe` / `pick_tool` consume the KB internally — reach for these only to
read a category raw. Category JSON can be large; pull one deliberately.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# mcp-server/src/praetor/tools/knowledge_access.py -> parents[1] == praetor pkg
KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"


def knowledge_entries() -> list[dict]:
    """Pure: every category's {name, contexts, description}, sorted. [] if no dir."""
    if not KNOWLEDGE_DIR.exists():
        return []
    out = []
    for f in sorted(KNOWLEDGE_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            out.append({
                "name": f.stem,
                "contexts": len(data.get("contexts") or {}),
                "description": (data.get("description") or data.get("category") or "")[:120],
            })
        except Exception as e:  # a malformed KB file must not hide the rest
            out.append({"name": f.stem, "contexts": 0, "description": f"parse error: {e}"})
    return out


def read_knowledge(category: str) -> dict:
    """Pure: {name, data} for one category's JSON, or {error, available}. Traversal-safe."""
    if not category or "/" in category or "\\" in category:
        return {"error": "invalid category name"}
    path = (KNOWLEDGE_DIR / f"{category}.json").resolve()
    try:
        path.relative_to(KNOWLEDGE_DIR.resolve())
    except ValueError:
        return {"error": "invalid category name"}
    if not path.exists():
        return {"error": f"unknown category {category!r}",
                "available": [e["name"] for e in knowledge_entries()]}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"error": f"parse error in {category}: {e}"}
    return {"name": category, "data": data}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def list_knowledge() -> dict:
        """List the knowledge-base probe classes (categories) as a TOOL.

        Each entry is {name, contexts, description}. Point
        `auto_probe(categories=[...])` at the names, or read one raw with
        `get_knowledge(name)`. Same content as the `burp://knowledge/index`
        resource, offered as a tool for hosts without MCP-resource support.
        """
        entries = knowledge_entries()
        return {"count": len(entries), "categories": entries}

    @mcp.tool()
    async def get_knowledge(category: str) -> dict:
        """Load one knowledge category's raw JSON (probes + matchers + craft guidance).

        Call `list_knowledge()` first for names. Returns {name, data} or
        {error, available}. Note: category JSON can be large — `auto_probe`
        already consumes the KB internally; read raw only when you need it.

        Args:
            category: category file stem, e.g. 'sqli', 'ssrf', 'idor'.
        """
        return read_knowledge(category)
