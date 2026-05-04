"""MCP Resources surface — read-only context the LLM can attach to its prompt.

Resources expose the durable artefacts the operator builds up over an
engagement (scope, findings, knowledge index, hunt rules) as URI-addressable
context, so the agent can pull them without spending tool budget.

URI scheme:
  burp://rules/hunting       — always-active hunting rules
  burp://rules/engineering   — always-active engineering rules
  burp://skills/<name>       — skill markdown by file stem
  burp://knowledge/index     — list of knowledge-base categories
  burp://knowledge/<name>    — raw JSON for one category
  burp://intel/<domain>/<kind>  — saved target intel (profile/findings/coverage/etc)
  burp://findings/<domain>   — current findings list
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP


REPO_ROOT = Path(__file__).resolve().parents[4]
RULES_DIR = REPO_ROOT / ".claude" / "rules"
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"
INTEL_ROOT = REPO_ROOT / ".burp-intel"

# Whitelist of intel kinds the resource layer will surface. Keeps the URI
# space discoverable and prevents path traversal.
_INTEL_KINDS = {
    "profile", "endpoints", "coverage", "findings",
    "fingerprint", "patterns", "notes",
}


def _safe_relative(base: Path, name: str) -> Path | None:
    candidate = (base / name).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None
    return candidate


def register(mcp: FastMCP):

    @mcp.resource("burp://rules/hunting")
    def rules_hunting() -> str:
        """The 28 always-active hunting rules (HARD/DEFAULT/ADVISORY)."""
        path = RULES_DIR / "hunting.md"
        return path.read_text() if path.exists() else "hunting.md not found"

    @mcp.resource("burp://rules/engineering")
    def rules_engineering() -> str:
        """The 4 engineering rules: think first, simplicity, surgical, goal-driven."""
        path = RULES_DIR / "engineering.md"
        return path.read_text() if path.exists() else "engineering.md not found"

    @mcp.resource("burp://skills/{name}")
    def skill_markdown(name: str) -> str:
        """Read a single skill file from .claude/skills/ by name (without .md)."""
        if not name or "/" in name or "\\" in name:
            return "invalid skill name"
        path = _safe_relative(SKILLS_DIR, f"{name}.md")
        if path is None or not path.exists():
            available = sorted(p.stem for p in SKILLS_DIR.glob("*.md"))
            return f"skill {name!r} not found. Available: {', '.join(available)}"
        return path.read_text()

    @mcp.resource("burp://knowledge/index")
    def knowledge_index() -> str:
        """List of all knowledge-base categories with their context counts."""
        rows = []
        for f in sorted(KNOWLEDGE_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                ctx_count = len(data.get("contexts") or {})
                desc = data.get("description") or data.get("category") or ""
                rows.append(f"- {f.stem} ({ctx_count} contexts) — {desc[:80]}")
            except Exception as e:
                rows.append(f"- {f.stem} — parse error: {e}")
        return "Knowledge base categories:\n" + "\n".join(rows)

    @mcp.resource("burp://knowledge/{category}")
    def knowledge_category(category: str) -> str:
        """Raw JSON for one knowledge category (probes + matchers + craft guidance)."""
        if not category or "/" in category or "\\" in category:
            return "invalid category name"
        path = _safe_relative(KNOWLEDGE_DIR, f"{category}.json")
        if path is None or not path.exists():
            return f"unknown category: {category}"
        return path.read_text()

    @mcp.resource("burp://intel/{domain}/{kind}")
    def intel_resource(domain: str, kind: str) -> str:
        """Read .burp-intel/<domain>/<kind>.{json,md} (profile/findings/coverage/notes/etc)."""
        if kind not in _INTEL_KINDS:
            return f"unknown intel kind {kind!r}. Allowed: {', '.join(sorted(_INTEL_KINDS))}"
        if not domain or "/" in domain or "\\" in domain or domain.startswith("."):
            return "invalid domain"
        domain_dir = _safe_relative(INTEL_ROOT, domain)
        if domain_dir is None or not domain_dir.exists():
            return f"no intel for {domain!r} yet — run recon to populate it"
        ext = "md" if kind == "notes" else "json"
        path = domain_dir / f"{kind}.{ext}"
        if not path.exists():
            return f"{kind}.{ext} not yet recorded for {domain}"
        return path.read_text()

    @mcp.resource("burp://findings/{domain}")
    def findings_for_domain(domain: str) -> str:
        """Saved findings JSON for one domain (alias of burp://intel/<domain>/findings)."""
        if not domain or "/" in domain or "\\" in domain or domain.startswith("."):
            return "invalid domain"
        domain_dir = _safe_relative(INTEL_ROOT, domain)
        if domain_dir is None:
            return "invalid domain"
        path = domain_dir / "findings.json"
        if not path.exists():
            return f"no findings recorded for {domain} yet"
        return path.read_text()
