"""Per-item status: persistence, render, run-plan ordering, verdict mapping.

The operator confirms each test case; status is persisted in
`.burp-intel/<domain>/checklist.json` as `{standard}:{item_id} -> {status, note, at}`.
Auto (coverage) touch is overlaid at render time. Everything here is pure except
the two `.burp-intel` load/save helpers.
"""

from __future__ import annotations

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


# Rule-29 high-value categories, per standard, for the high-impact ordering.
_HIGH_VALUE = {
    "wstg": ("ATHZ", "ATHN", "INPV", "BUSL", "APIT", "SESS"),
    "owasp_top10": ("A01", "A05", "A07", "A06"),
    "api_top10": ("API1", "API5", "API3", "API2"),
    "ai_testing": ("APP", "MODEL"),
    "mastg": ("AUTH", "STORAGE", "PLATFORM"),
}


def next_open_items(standard: str, cases: list[dict[str, str]],
                    item_status: dict[str, dict[str, str]],
                    touched: set[str], mode: str = "full_coverage") -> list[dict[str, str]]:
    """Pure: the OPEN test cases to run next, ordered by engagement mode.

    An item is OPEN unless it has an explicit confirmed/finding/not_applicable
    status. `full_coverage`/`checklist` -> catalog order; `high_impact` ->
    Rule-29 high-value categories first (and drops pure-manual items).
    """
    done = {k.split(":", 1)[1] for k, v in item_status.items()
            if v.get("status") in ("confirmed", "finding", "not_applicable")}
    open_items = [c for c in cases if c["id"] not in done]
    if mode == "high_impact":
        hv = _HIGH_VALUE.get(standard, ())
        open_items = [c for c in open_items if "manual" not in c["tool"].lower()]
        open_items.sort(key=lambda c: hv.index(c["category"]) if c["category"] in hv else len(hv))
    return open_items


# VerdictResult.verdict -> checklist item status. INCONCLUSIVE/SUSPECTED/ERROR
# leave the item OPEN (not closed) per Rule 13b/19a — a non-decisive probe is not
# a completed test case.
_VERDICT_TO_STATUS: dict[str, str] = {
    "CONFIRMED": "finding",       # a real finding
    "FAILED": "confirmed",        # ran + valid negative -> test case done, clean
    "SUSPECTED": "open",          # needs manual confirmation
    "INCONCLUSIVE": "open",       # test validity unproven -> keep testing
    "ERROR": "open",              # blocked -> ask operator
}
_VERDICT_NOTE: dict[str, str] = {
    "CONFIRMED": "auto: confirmed by probe",
    "FAILED": "auto: tested, valid negative",
    "SUSPECTED": "auto: suspected — needs manual confirmation",
    "INCONCLUSIVE": "auto: inconclusive — test validity unproven, keep testing",
    "ERROR": "auto: probe errored/blocked — unblock and re-run (Rule 32a)",
}


def verdict_to_checklist_status(verdict: str) -> tuple[str, str]:
    """Pure: map a VerdictResult verdict to (checklist_status, note).

    Returns status 'open' for non-decisive verdicts (the item is NOT closed).
    """
    v = (verdict or "").upper()
    return _VERDICT_TO_STATUS.get(v, "open"), _VERDICT_NOTE.get(v, "auto: unknown verdict")
