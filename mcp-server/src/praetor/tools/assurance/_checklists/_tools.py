"""MCP tools that walk, confirm, and auto-drive the per-test-case checklists."""

from __future__ import annotations

from typing import Any

from ._catalogs import checklist_for
from ._status import (
    _ITEM_STATES,
    _load_status,
    _save_status,
    next_open_items,
    render_checklist,
    verdict_to_checklist_status,
)


def register(mcp: Any) -> None:
    from ..coverage_map import _tested_classes
    from .._standards import STANDARDS, category_of

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

    @mcp.tool()
    async def checklist_autotest(domain: str, standard: str = "wstg",
                                 mode: str = "full_coverage", limit: int = 25) -> str:
        """Drive the checklist: the ordered run-plan of OPEN test cases to execute.

        Walks the catalog and returns the next OPEN items (skipping confirmed /
        finding / not_applicable), each with the Praetor tool to run — so the
        orchestrator executes each, then records the result via
        `checklist_update`. This is the "test every case" loop.

        Ordering follows the Phase-0 engagement mode: `high_impact` puts the
        Rule-29 high-value categories first (and drops pure-manual items);
        `full_coverage` / `checklist` walk in catalog order.

        Args:
            domain: target.
            standard: wstg / ai_testing / owasp_top10 / api_top10 / mastg.
            mode: full_coverage | high_impact | checklist.
            limit: max items in this plan (page through the rest as they close).
        """
        cases = checklist_for(standard)
        if standard not in STANDARDS:
            return f"unknown standard '{standard}'; valid: {sorted(STANDARDS.keys())}"
        if not cases:
            return (f"{STANDARDS[standard]['name']} has no per-test-case catalog; "
                    f"use coverage_status(domain) for the category heatmap.")
        status = _load_status(domain)
        touched: set[str] = set()
        if domain:
            for cls in _tested_classes(domain):
                cat = category_of(standard, cls)
                if cat:
                    touched.add(cat)
        plan = next_open_items(standard, cases, status, touched, mode)
        total_open = len(plan)
        plan = plan[:max(1, limit)]
        lines = [f"# Auto-test plan — {STANDARDS[standard]['name']} ({mode})",
                 f"{total_open} OPEN test cases; next {len(plan)}:"]
        for it in plan:
            lines.append(f"  {it['id']} [{it['category']}]  {it['name']}  -> RUN {it['tool']}")
        lines.append("")
        lines.append("For each: run the tool, grade on the response BODY (Rule 13a), then "
                     "checklist_update(domain, standard, item_id, status=confirmed|finding|"
                     "not_applicable, note=...). A blocker is an ASK, not a skip (Rule 32a).")
        return "\n".join(lines)

    @mcp.tool()
    async def checklist_record_batch(domain: str, standard: str, results: list) -> str:
        """Record many auto-test results at once — closes the run loop efficiently.

        After `checklist_autotest` gives the plan and you run each item's tool,
        pass the outcomes here in ONE call. Each result is a dict with `item_id`
        plus EITHER `verdict` (a VerdictResult verdict — CONFIRMED/FAILED/
        SUSPECTED/INCONCLUSIVE/ERROR, mapped automatically) OR an explicit `status`
        (confirmed/finding/not_applicable). Optional `note` (evidence index).
        Non-decisive verdicts (SUSPECTED/INCONCLUSIVE/ERROR) leave the item OPEN —
        they are not a completed test (Rule 13b/19a).

        Args:
            domain: target.
            standard: wstg / ai_testing / owasp_top10 / api_top10 / mastg.
            results: [{item_id, verdict|status, note?}, ...].
        """
        from datetime import datetime, timezone
        items = _load_status(domain)
        closed, left_open, bad = 0, 0, 0
        for r in results or []:
            if not isinstance(r, dict) or not r.get("item_id"):
                bad += 1
                continue
            note = str(r.get("note", "")).strip()
            if r.get("verdict"):
                status, auto_note = verdict_to_checklist_status(r["verdict"])
                note = note or auto_note
            else:
                status = str(r.get("status", "")).lower()
            if status not in ("confirmed", "finding", "not_applicable"):
                left_open += 1  # SUSPECTED/INCONCLUSIVE/ERROR/open -> stays open
                continue
            if status == "not_applicable" and not note:
                note = "auto: marked N/A"
            items[f"{standard}:{r['item_id']}"] = {
                "status": status, "note": note,
                "at": datetime.now(timezone.utc).isoformat()}
            closed += 1
        _save_status(domain, items)
        return (f"recorded {closed} test case(s); {left_open} left OPEN "
                f"(non-decisive/needs work)" + (f"; {bad} malformed" if bad else "") + ".")
