"""Detailed per-test-case checklists for the OWASP standards.

`_standards.py` tracks coverage at the CATEGORY level (what did we NOT test).
This adds the test-case granularity the operator asked for: every individual
test in a guide, its parent category, and the Praetor tool/approach that runs
it — so a checklist can be walked item by item and each confirmed.

A checklist entry: {id, category, name, tool}. `category` matches a key in the
corresponding `_standards.STANDARDS[<std>]["categories"]` so a per-item status
can roll up to the category heatmap. `tool` is the suggested Praetor entry point
an auto-test driver would invoke for that item (advisory, not executed here).

Seeded: `ai_testing` (OWASP AI Testing Guide, 32 tests, complete). WSTG and MASTG
catalogs plug into the same shape.
"""

from __future__ import annotations

from typing import Any

# OWASP AI Testing Guide — 4 domains, 32 tests (mas.owasp.org / AI Testing Guide).
_AI_CHECKLIST: list[dict[str, str]] = [
    # AI Application Testing (14)
    {"id": "AITG-APP-01", "category": "APP", "name": "Prompt injection", "tool": "run_web_llm_owasp_top10 / probe_sse_injection"},
    {"id": "AITG-APP-02", "category": "APP", "name": "Indirect prompt injection", "tool": "inspect_for_prompt_injection"},
    {"id": "AITG-APP-03", "category": "APP", "name": "Sensitive data leakage", "tool": "run_web_llm_owasp_top10"},
    {"id": "AITG-APP-04", "category": "APP", "name": "Input leakage", "tool": "run_garak"},
    {"id": "AITG-APP-05", "category": "APP", "name": "Unsafe outputs (output handling into a sink)", "tool": "probe_xss_executed"},
    {"id": "AITG-APP-06", "category": "APP", "name": "Agentic behavior limits / excessive agency", "tool": "probe_cua_injection_surface"},
    {"id": "AITG-APP-07", "category": "APP", "name": "System-prompt disclosure", "tool": "run_garak"},
    {"id": "AITG-APP-08", "category": "APP", "name": "Embedding manipulation", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-APP-09", "category": "APP", "name": "Model extraction (via app)", "tool": "run_garak"},
    {"id": "AITG-APP-10", "category": "APP", "name": "Content bias", "tool": "run_garak"},
    {"id": "AITG-APP-11", "category": "APP", "name": "Hallucinations", "tool": "run_garak"},
    {"id": "AITG-APP-12", "category": "APP", "name": "Toxic outputs", "tool": "run_garak"},
    {"id": "AITG-APP-13", "category": "APP", "name": "Over-reliance", "tool": "manual / run_owasp_asi_top10"},
    {"id": "AITG-APP-14", "category": "APP", "name": "Explainability", "tool": "manual"},
    # AI Model Testing (7)
    {"id": "AITG-MOD-01", "category": "MODEL", "name": "Evasion attacks", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-02", "category": "MODEL", "name": "Runtime model poisoning", "tool": "run_garak"},
    {"id": "AITG-MOD-03", "category": "MODEL", "name": "Poisoned training sets", "tool": "manual / data review"},
    {"id": "AITG-MOD-04", "category": "MODEL", "name": "Membership inference", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-05", "category": "MODEL", "name": "Inversion attacks", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-06", "category": "MODEL", "name": "Robustness evaluation", "tool": "run_garak"},
    {"id": "AITG-MOD-07", "category": "MODEL", "name": "Goal alignment", "tool": "run_owasp_asi_top10"},
    # AI Infrastructure Testing (6)
    {"id": "AITG-INF-01", "category": "INFRA", "name": "Supply-chain tampering", "tool": "run_trivy / run_syft"},
    {"id": "AITG-INF-02", "category": "INFRA", "name": "Resource exhaustion", "tool": "test_rate_limit"},
    {"id": "AITG-INF-03", "category": "INFRA", "name": "Plugin boundary violations", "tool": "probe_mcp_server_attacks"},
    {"id": "AITG-INF-04", "category": "INFRA", "name": "Capability misuse", "tool": "run_owasp_asi_top10"},
    {"id": "AITG-INF-05", "category": "INFRA", "name": "Fine-tuning poisoning", "tool": "manual / data review"},
    {"id": "AITG-INF-06", "category": "INFRA", "name": "Development-time model theft", "tool": "manual / access review"},
    # AI Data Testing (5)
    {"id": "AITG-DAT-01", "category": "DATA", "name": "Training-data exposure", "tool": "run_web_llm_owasp_top10"},
    {"id": "AITG-DAT-02", "category": "DATA", "name": "Runtime data exfiltration", "tool": "run_garak"},
    {"id": "AITG-DAT-03", "category": "DATA", "name": "Dataset diversity / coverage", "tool": "manual / data review"},
    {"id": "AITG-DAT-04", "category": "DATA", "name": "Harmful content in datasets", "tool": "manual / data review"},
    {"id": "AITG-DAT-05", "category": "DATA", "name": "Data minimization / consent", "tool": "manual / privacy review"},
]

CHECKLISTS: dict[str, list[dict[str, str]]] = {
    "ai_testing": _AI_CHECKLIST,
    # "wstg": _WSTG_CHECKLIST,   # follows (WSTG-<CAT>-NN)
    # "mastg": _MASTG_CHECKLIST, # follows (MASTG-TEST-NNNN -> MASVS cat)
}


def checklist_for(standard: str) -> list[dict[str, str]]:
    return CHECKLISTS.get(standard, [])


# Per-item status the operator confirms, persisted in .burp-intel/<domain>/checklist.json.
# {standard}:{item_id} -> {status, note, at}. Auto (coverage) is overlaid at render.
_ITEM_STATES = {"confirmed", "finding", "not_applicable", "open"}
_ITEM_BOX = {"confirmed": "[x]", "finding": "[!]", "not_applicable": "[-]", "open": "[ ]"}


def _load_status(domain: str) -> dict[str, dict[str, str]]:
    if not domain:
        return {}
    from praetor.tools.report.lifecycle import load_intel
    return load_intel(domain, "checklist").get("items", {}) or {}


def _save_status(domain: str, items: dict[str, dict[str, str]]) -> None:
    from praetor.tools.intel import _intel_path
    from praetor.tools.notes._findings_io import atomic_write_json
    d = _intel_path(domain)
    d.mkdir(parents=True, exist_ok=True)
    atomic_write_json(d / "checklist.json", {"items": items})


def render_checklist(standard: str, standard_name: str, cases: list[dict[str, str]],
                     tested_categories: set[str] | None = None,
                     item_status: dict[str, dict[str, str]] | None = None) -> str:
    """Render the detailed per-test-case checklist. Pure.

    Status precedence per item: an explicit operator status in `item_status`
    (confirmed / finding / not_applicable) wins; else [~] if the item's category
    was touched by coverage (`tested_categories`); else [ ] open (Rule 19a).
    """
    touched = tested_categories or set()
    status = item_status or {}
    lines = [f"# {standard_name} — detailed checklist ({len(cases)} tests)", ""]
    by_cat: dict[str, list[dict[str, str]]] = {}
    for c in cases:
        by_cat.setdefault(c["category"], []).append(c)
    open_n = done_n = 0
    for cat, items in by_cat.items():
        lines.append(f"## {cat}")
        for it in items:
            st = status.get(f"{standard}:{it['id']}", {})
            explicit = st.get("status")
            if explicit in ("confirmed", "finding", "not_applicable"):
                box = _ITEM_BOX[explicit]
                done_n += 1
                note = f"  ({st.get('note')})" if st.get("note") else ""
            elif it["category"] in touched:
                box = "[~]"  # category touched, item not individually confirmed
                note = ""
            else:
                box = "[ ]"
                open_n += 1
                note = ""
            lines.append(f"  {box} {it['id']}  {it['name']}  -> {it['tool']}{note}")
        lines.append("")
    lines.append(f"{done_n} confirmed/NA, {len(cases) - done_n - open_n} category-touched, "
                 f"{open_n} OPEN of {len(cases)}. "
                 f"[x]=confirmed [!]=finding [-]=N/A [~]=category touched [ ]=untested (Rule 19a).")
    return "\n".join(lines)


def register(mcp: Any) -> None:
    from .coverage_map import _tested_classes
    from ._standards import STANDARDS, category_of

    @mcp.tool()
    async def checklist(standard: str = "ai_testing", domain: str = "") -> str:
        """Detailed per-test-case checklist for an OWASP standard.

        Walks every individual test in the guide (id, name, and the Praetor tool
        that runs it), grouped by category. With `domain`, marks each item's
        category as touched/open from coverage.json so the operator sees exactly
        which test cases remain. Standards with a detailed catalog: ai_testing
        (32 tests); others fall back to their category list.

        Args:
            standard: ai_testing (detailed) | owasp_top10 | api_top10 | wstg | mastg.
            domain: optional target for tested/untested marking.
        """
        cases = checklist_for(standard)
        if standard not in STANDARDS:
            return (f"unknown standard '{standard}'; "
                    f"valid: {sorted(STANDARDS.keys())}")
        name = STANDARDS[standard]["name"]
        if not cases:
            cats = STANDARDS[standard]["categories"]
            return (f"# {name} — no per-test-case catalog yet; "
                    f"{len(cats)} categories tracked. Use coverage_status(domain) "
                    f"for the category heatmap.")
        touched: set[str] = set()
        if domain:
            for cls in _tested_classes(domain):
                cat = category_of(standard, cls)
                if cat:
                    touched.add(cat)
        return render_checklist(standard, name, cases, touched, _load_status(domain))

    @mcp.tool()
    async def checklist_update(domain: str, standard: str, item_id: str,
                               status: str, note: str = "") -> str:
        """Confirm/complete one checklist test case (operator-owned status).

        Walk the checklist item by item: run each item's mapped tool, then record
        the operator-confirmed result here so it sticks (auto coverage marks a
        category touched; this marks the SPECIFIC test case done). Use this in the
        confirm loop — present the item + evidence, ask the operator, then set it.

        Args:
            domain: target.
            standard: ai_testing / owasp_top10 / api_top10 / wstg / mastg.
            item_id: the test-case id, e.g. AITG-APP-01.
            status: confirmed | finding | not_applicable | open.
            note: short evidence / reason (required for not_applicable).
        """
        if status not in _ITEM_STATES:
            return f"status must be one of {sorted(_ITEM_STATES)}"
        if status == "not_applicable" and not note.strip():
            return "not_applicable requires a note (why it doesn't apply) — Rule 19a."
        from datetime import datetime, timezone
        items = _load_status(domain)
        key = f"{standard}:{item_id}"
        if status == "open":
            items.pop(key, None)
        else:
            items[key] = {"status": status, "note": note.strip(),
                          "at": datetime.now(timezone.utc).isoformat()}
        _save_status(domain, items)
        return f"checklist {key} -> {status}" + (f" ({note.strip()})" if note.strip() else "")
