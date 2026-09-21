"""Cross-host skill access — list and fetch the `.claude/skills/*.md` library as MCP
TOOLS (not only resources).

The same skills are exposed as MCP Resources (`burp://skills/{name}` /
`burp://skills/index`) in `resources_mcp.py`, but not every MCP host supports the
resource primitive — several non-Claude clients (Codex, Gemini CLI, ...) surface
tools well before resources. Exposing `list_skills` / `get_skill` as tools means
any MCP client can discover and load Praetor's procedural playbooks
(verify-finding, chain-findings, lab-solve, ...) regardless of resource support.

`skill_entries` and `read_skill` are pure and unit-tested; the tools are thin
async wrappers over them.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# mcp-server/src/praetor/tools/skills_access.py -> parents[4] == repo root
SKILLS_DIR = Path(__file__).resolve().parents[4] / ".claude" / "skills"

_DESC = re.compile(r"^description:\s*(.+)$", re.MULTILINE)


def _description(text: str) -> str:
    """The skill's frontmatter `description:` (first line), or ''."""
    m = _DESC.search(text)
    return m.group(1).strip() if m else ""


def skill_entries() -> list[dict]:
    """Pure: every skill's {name, description}, sorted by name. [] if no dir."""
    if not SKILLS_DIR.exists():
        return []
    out = []
    for p in sorted(SKILLS_DIR.glob("*.md")):
        try:
            desc = _description(p.read_text(encoding="utf-8"))
        except OSError:
            desc = ""
        out.append({"name": p.stem, "description": desc})
    return out


def read_skill(name: str) -> dict:
    """Pure: {name, markdown} for one skill, or {error, available}. Path-traversal safe."""
    if not name or "/" in name or "\\" in name:
        return {"error": "invalid skill name"}
    path = (SKILLS_DIR / f"{name}.md").resolve()
    try:
        path.relative_to(SKILLS_DIR.resolve())
    except ValueError:
        return {"error": "invalid skill name"}
    if not path.exists():
        return {"error": f"skill {name!r} not found",
                "available": [e["name"] for e in skill_entries()]}
    return {"name": name, "markdown": path.read_text(encoding="utf-8")}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def list_skills() -> dict:
        """List Praetor's skill library — procedural playbooks the agent loads on demand.

        Skills live in `.claude/skills/` (verify-finding, chain-findings, lab-solve,
        craft-payload, ...) and encode HOW to do a task; the MCP tools are WHAT it
        does. Returns each skill's name + one-line description. Load one's full text
        with `get_skill(name)`. Same content as the `burp://skills/index` resource,
        offered as a tool so hosts without MCP-resource support can still use it.
        """
        entries = skill_entries()
        if not entries:
            return {"count": 0, "skills": [], "note": f"no skills found under {SKILLS_DIR}"}
        return {"count": len(entries), "skills": entries}

    @mcp.tool()
    async def get_skill(name: str) -> dict:
        """Load one skill's full markdown by name (file stem, no `.md`).

        Mirrors the `burp://skills/<name>` resource. Call `list_skills()` first for
        the available names. Returns {name, markdown} or {error, available}.

        Args:
            name: skill file stem, e.g. 'verify-finding', 'lab-solve'.
        """
        return read_skill(name)
