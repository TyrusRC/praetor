"""build_engagement_checklist — one scoped, combined checklist markdown file.

The `/pentest` deliverable: a single markdown file that merges the relevant
OWASP standards for the target's scope PLUS the knowledge-base edge-case classes,
so the operator gets the full test list to work (and tick off) in one place.

Scope → standards:
  web    → OWASP Top 10 (2025) + WSTG v4.2
  api    → OWASP API Security Top 10 (2023)
  mobile → OWASP MASVS v2 / MASTG
  llm    → OWASP AI Testing Guide
Every scope also gets its slice of the KB test-class catalog as "edge cases".
Written to `.burp-intel/<domain>/reports/<domain>-checklist.md`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.scan._constants import KNOWLEDGE_DIR
from praetor.tools.workspace import ensure_workspace

from .._standards import STANDARDS
from ._catalogs import checklist_for
from ._status import _load_status

_SCOPE_STANDARDS: dict[str, list[str]] = {
    "web": ["owasp_top10", "wstg"],
    "api": ["api_top10"],
    "mobile": ["mastg"],
    "llm": ["ai_testing"],
    "ai": ["ai_testing"],
}

# KB categories that belong to a non-web scope; everything else is web/api.
_MOBILE_KB = {"mobile_api", "mobile_deeplink", "webview_injection", "push_notification"}
_LLM_KB = {"ai_prompt_injection", "web_llm", "rag_injection", "echoleak",
           "mcp_server_attacks", "mcp_tool_poisoning", "vector_db_injection",
           "a2a_protocol", "unsafe_consumption", "sse_injection"}


def _norm_scope(scope: list[str] | str) -> list[str]:
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.replace(",", " ").split()]
    out = [s.lower() for s in scope if s]
    return out or ["web"]


def _standards_for(scope: list[str]) -> list[str]:
    seen: list[str] = []
    for s in scope:
        for std in _SCOPE_STANDARDS.get(s, []):
            if std not in seen:
                seen.append(std)
    return seen or ["owasp_top10", "wstg"]


def _kb_categories() -> list[str]:
    try:
        return sorted(p.stem for p in KNOWLEDGE_DIR.glob("*.json")
                      if not p.stem.startswith("_"))
    except OSError:
        return []


def _scoped_kb(scope: list[str]) -> list[str]:
    want_web = "web" in scope or "api" in scope
    want_mobile = "mobile" in scope
    want_llm = "llm" in scope or "ai" in scope
    out = []
    for c in _kb_categories():
        if c in _MOBILE_KB:
            if want_mobile:
                out.append(c)
        elif c in _LLM_KB:
            if want_llm:
                out.append(c)
        elif want_web:
            out.append(c)
    return out


def _checked(status: dict, standard: str, item_id: str) -> str:
    row = status.get(f"{standard}:{item_id}") or {}
    st = str(row.get("status", "")).lower()
    if st in ("confirmed", "finding", "pass", "tested", "covered"):
        return "x"
    return " "


def render_engagement_md(domain: str, scope: list[str]) -> str:
    scope = _norm_scope(scope)
    standards = _standards_for(scope)
    status = _load_status(domain)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f"# Pentest Checklist — {domain}",
        "",
        f"- **Scope:** {', '.join(scope)}",
        f"- **Generated:** {today}",
        f"- **Standards:** {', '.join(STANDARDS[s]['name'] for s in standards)}",
        "",
        "Work top to bottom; tick each item as it is tested "
        "(`checklist_update(domain, standard, item_id, status=...)` persists status "
        "and this file regenerates). `[x]` = tested/confirmed, `[ ]` = open.",
        "",
    ]

    total = tested = 0
    for std in standards:
        cases = checklist_for(std)
        if not cases:
            continue
        lines += [f"## {STANDARDS[std]['name']}", ""]
        lines += ["| ✓ | ID | Test | Tool |", "|---|---|---|---|"]
        for c in cases:
            total += 1
            mark = _checked(status, std, c.get("id", ""))
            if mark == "x":
                tested += 1
            lines.append(
                f"| [{mark}] | {c.get('id','')} | {c.get('name','')} | "
                f"`{c.get('tool','auto_probe')}` |")
        lines.append("")

    kb = _scoped_kb(scope)
    if kb:
        lines += [
            "## Edge cases — knowledge-base test classes",
            "",
            "Beyond the standard checklist: every applicable Praetor KB probe class. "
            "Run with `auto_probe(categories=['<class>'])`.",
            "",
            "| ✓ | Class | Run |", "|---|---|---|",
        ]
        for cat in kb:
            total += 1
            lines.append(f"| [ ] | {cat} | `auto_probe(categories=['{cat}'])` |")
        lines.append("")

    lines += [
        "---",
        f"**{total} test items** ({tested} marked tested). "
        "Update coverage with `coverage_status(domain)`; auto-plan the next open "
        "items with `checklist_autotest(domain, standard)`.",
    ]
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def build_engagement_checklist(domain: str, scope: str = "web") -> str:
        """Write ONE combined, scoped pentest checklist markdown file for a target.

        Merges the OWASP standards for the given scope PLUS the knowledge-base
        edge-case classes into a single full-list deliverable and writes it to
        `.burp-intel/<domain>/reports/<domain>-checklist.md`. This is the file
        the `/pentest` flow hands back.

        Scope → standards: web = Top 10 (2025) + WSTG v4.2; api = API Top 10
        (2023); mobile = MASVS v2 / MASTG; llm = AI Testing Guide. Each scope also
        pulls its slice of the KB test-class catalog. Latest versions throughout.

        Args:
            domain: Target domain (workspace + filename key).
            scope: Space/comma-separated scope — any of web, api, mobile, llm
                (e.g. "web api" or "web mobile"). Default "web".
        """
        scope_list = _norm_scope(scope)
        md = render_engagement_md(domain, scope_list)
        reports = ensure_workspace(domain)["reports"]
        out = reports / f"{_safe(domain)}-checklist.md"
        try:
            out.write_text(md, encoding="utf-8")
        except OSError as exc:
            return f"Error writing checklist: {exc}"
        n_items = md.count("| [")
        return (f"Wrote {out} — scope [{', '.join(scope_list)}], {n_items} test items.\n"
                f"Standards: {', '.join(STANDARDS[s]['name'] for s in _standards_for(scope_list))}"
                f" + KB edge cases.")


def _safe(domain: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain) or "target"
