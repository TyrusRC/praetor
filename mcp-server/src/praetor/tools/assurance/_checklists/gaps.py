"""checklist_gaps — single view of what's tested, what's missing, and what to run next.

The operator's answer to "did you test everything?" Merges checklist status,
coverage.json, findings.json, and test_journal.jsonl into one table with
clear TESTED/MISSING/FINDING labels.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._catalogs import checklist_for
from ._status import _load_status


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def checklist_gaps(
        domain: str,
        standard: str = "wstg",
        show: str = "missing",
    ) -> str:
        """Show exactly which checklist items are tested vs missing.

        The single view for "did you test everything, and what did you miss?"
        Each item shows its status, the tool that should test it, and whether
        a finding or test-journal entry exists for it.

        Args:
            domain: Target domain.
            standard: wstg / ai_testing / owasp_top10 / api_top10 / mastg.
            show: missing (default — only gaps) / all / tested / findings.
        """
        from .._standards import STANDARDS, category_of
        from ..coverage_map import _tested_classes

        if standard not in STANDARDS:
            return f"Unknown standard '{standard}'; valid: {sorted(STANDARDS.keys())}"

        cases = checklist_for(standard)
        if not cases:
            return (f"{STANDARDS[standard]['name']} has no per-test-case catalog; "
                    f"use coverage_status(domain) for the category heatmap.")

        status = _load_status(domain)
        touched_cats: set[str] = set()
        if domain:
            for cls in _tested_classes(domain):
                cat = category_of(standard, cls)
                if cat:
                    touched_cats.add(cat)

        # Load test journal for evidence cross-reference
        from praetor.tools.intel._internals import _intel_path
        base = _intel_path(domain)
        journal_classes: set[str] = set()
        journal_path = base / "test_journal.jsonl"
        if journal_path.exists():
            try:
                for line in journal_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            e = json.loads(line)
                            journal_classes.add(e.get("vuln_class", ""))
                        except json.JSONDecodeError:
                            pass
            except OSError:
                pass

        # Load findings for cross-reference
        finding_types: set[str] = set()
        findings_path = base / "findings.json"
        if findings_path.exists():
            try:
                fdata = json.loads(findings_path.read_text(encoding="utf-8"))
                for f in (fdata if isinstance(fdata, list) else fdata.get("findings", [])):
                    finding_types.add(f.get("vuln_type", ""))
            except (OSError, json.JSONDecodeError):
                pass

        # Build per-item status
        items: list[dict[str, str]] = []
        for case in cases:
            item_id = case["id"]
            cat = case.get("category", "")
            key = f"{standard}:{item_id}"
            tool = case.get("tool", "auto_probe")

            if key in status:
                st = status[key]["status"]
                note = status[key].get("note", "")
                label = "FINDING" if st == "finding" else "TESTED" if st in ("confirmed", "not_applicable") else "OPEN"
            elif cat in touched_cats:
                label = "TOUCHED"
                st = "category_covered"
                note = "category touched by auto_probe (not per-item confirmed)"
            else:
                label = "MISSING"
                st = "open"
                note = ""

            items.append({
                "id": item_id,
                "name": case.get("name", ""),
                "category": cat,
                "tool": tool,
                "label": label,
                "status": st,
                "note": note,
                "has_journal": any(c in tool.lower() for c in journal_classes) if journal_classes else False,
            })

        # Filter
        if show == "missing":
            items = [i for i in items if i["label"] in ("MISSING", "TOUCHED")]
        elif show == "tested":
            items = [i for i in items if i["label"] in ("TESTED", "FINDING")]
        elif show == "findings":
            items = [i for i in items if i["label"] == "FINDING"]
        # "all" shows everything

        # Stats
        total = len(cases)
        tested = sum(1 for i in items if i["label"] in ("TESTED", "FINDING"))
        findings = sum(1 for i in items if i["label"] == "FINDING")
        missing = sum(1 for i in items if i["label"] == "MISSING")
        touched = sum(1 for i in items if i["label"] == "TOUCHED")

        # Count from full list for stats
        all_items_labels = []
        for case in cases:
            key = f"{standard}:{case['id']}"
            cat = case.get("category", "")
            if key in status:
                st = status[key]["status"]
                all_items_labels.append("FINDING" if st == "finding" else "TESTED" if st in ("confirmed", "not_applicable") else "OPEN")
            elif cat in touched_cats:
                all_items_labels.append("TOUCHED")
            else:
                all_items_labels.append("MISSING")

        total_tested = sum(1 for l in all_items_labels if l in ("TESTED", "FINDING"))
        total_findings = sum(1 for l in all_items_labels if l == "FINDING")
        total_missing = sum(1 for l in all_items_labels if l == "MISSING")
        total_touched = sum(1 for l in all_items_labels if l == "TOUCHED")

        lines = [f"# Checklist Gaps — {STANDARDS[standard]['name']}"]
        lines.append(f"Domain: {domain}")
        lines.append(f"Total: {total} items | TESTED: {total_tested} | FINDINGS: {total_findings} | "
                      f"TOUCHED (not confirmed): {total_touched} | MISSING: {total_missing}")
        pct = round(total_tested / total * 100) if total else 0
        lines.append(f"Coverage: {pct}% ({total_tested}/{total} confirmed)")
        lines.append("")

        if not items:
            if show == "missing":
                lines.append("No missing items — all checklist items are tested.")
            else:
                lines.append("No items match the filter.")
            return "\n".join(lines)

        lines.append(f"{'Label':<9} {'ID':<16} {'Category':<8} {'Name':<50} {'Tool':<30}")
        lines.append("-" * 120)
        for i in items:
            lines.append(
                f"{i['label']:<9} {i['id']:<16} {i['category']:<8} "
                f"{i['name'][:49]:<50} {i['tool'][:29]:<30}"
            )

        if show == "missing" and items:
            lines.append("")
            lines.append(f"Run these {len(items)} items to close the gaps.")
            lines.append("Use checklist_autotest(domain, standard) for the execution plan, "
                         "or run each tool directly and record via checklist_record_batch.")

        return "\n".join(lines)
