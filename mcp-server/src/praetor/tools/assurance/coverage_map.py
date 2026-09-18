"""standards_coverage — tested-vs-total heatmap against a security standard.

Rolls up coverage.json (tested tuples) + findings.json into a fixed
standard checklist so untested categories are visible, not just the ones
that produced a finding. This is the assurance view the commercial tier
(Pentera / NodeZero / BAS) sells: "what did we NOT test."

`build_heatmap` is pure (takes already-loaded data) for cheap testing;
`standards_coverage` is the @mcp.tool that does the disk I/O.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .._vuln_class import canonical
from ..report.lifecycle import load_intel
from ._standards import STANDARDS, category_of

# A finding counts toward coverage only once confirmed.
_CONFIRMED = {"confirmed"}


def build_heatmap(
    standard: str,
    tested_classes: set[str],
    findings: list[dict],
) -> dict[str, Any]:
    """Pure rollup. Every standard category is present in the output.

    status per category: 'findings' > 'tested' > 'untested'.
    coverage_pct = % of categories touched (tested or with a finding).
    """
    cats = STANDARDS[standard]["categories"]  # KeyError on unknown standard
    out: dict[str, dict[str, Any]] = {
        cid: {"name": name, "tested": 0, "findings": 0, "status": "untested"}
        for cid, name in cats.items()
    }

    for cls in tested_classes:
        cat = category_of(standard, cls)
        if cat and cat in out:
            out[cat]["tested"] += 1

    for f in findings:
        if f.get("status") not in _CONFIRMED:
            continue
        cat = category_of(standard, canonical(f.get("vuln_type", "")))
        if cat and cat in out:
            out[cat]["findings"] += 1

    touched = 0
    for cid, row in out.items():
        if row["findings"] > 0:
            row["status"] = "findings"
        elif row["tested"] > 0:
            row["status"] = "tested"
        if row["findings"] > 0 or row["tested"] > 0:
            touched += 1

    pct = round(100 * touched / len(cats)) if cats else 0
    return {
        "standard": standard,
        "standard_name": STANDARDS[standard]["name"],
        "coverage_pct": pct,
        "categories": out,
    }


def _tested_classes(domain: str) -> set[str]:
    """Distinct vuln classes with at least one tested tuple in coverage.json.

    On-disk coverage.json is {"entries":[{endpoint, parameter, category, ...}]}
    where `category` is the vuln class (see intel/save_load.py). Older/pattern
    shapes (vuln_class/class) are accepted as fallbacks.
    """
    cov = load_intel(domain, "coverage")
    rows = cov.get("entries") or cov.get("patterns") or []
    classes: set[str] = set()
    for e in rows:
        cls = e.get("category") or e.get("vuln_class") or e.get("class") or ""
        if cls:
            classes.add(canonical(cls))
    return classes


_STATUS_TAG = {
    "findings": "[FINDING ]",
    "tested":   "[tested  ]",
    "untested": "[UNTESTED]",
}


def render_coverage_status(domain: str, heatmaps: list[dict]) -> str:
    """Pure render of one or more standard heatmaps into a user-readable status.

    Surfaces the OWASP / WSTG tracking table the operator asked for: every
    category shown as findings / tested / untested, per-standard % touched, and a
    consolidated list of the UNTESTED gaps at the end.
    """
    lines = [f"# Test coverage status — {domain}", ""]
    untested: list[str] = []
    for hm in heatmaps:
        cats = hm.get("categories", {})
        name = hm.get("standard_name", hm.get("standard", "?"))
        touched = sum(1 for c in cats.values() if c.get("status") != "untested")
        lines.append(f"## {name} — {hm.get('coverage_pct', 0)}% "
                     f"({touched}/{len(cats)} categories touched)")
        for cid, c in cats.items():
            tag = _STATUS_TAG.get(c.get("status"), "[   ?   ]")
            bits = []
            if c.get("tested"):
                bits.append(f"{c['tested']} tested")
            if c.get("findings"):
                bits.append(f"{c['findings']} finding(s)")
            suffix = f" — {', '.join(bits)}" if bits else ""
            lines.append(f"  {tag} {cid}  {c.get('name', '')}{suffix}")
            if c.get("status") == "untested":
                untested.append(f"{hm.get('standard')}:{cid}")
        lines.append("")
    if untested:
        lines.append(f"UNTESTED gaps ({len(untested)}) — test or justify before "
                     f"claiming coverage: {', '.join(untested)}")
    else:
        lines.append("Every standard category has at least one test or finding.")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def coverage_status(domain: str, standards: list[str] | None = None) -> str:
        """User-readable test-coverage status across security standards.

        Rolls up coverage.json + confirmed findings into the OWASP Top 10 / API
        Top 10 / WSTG checklists in ONE readable view so the operator can see, at
        any checkpoint, what has been tested, what produced findings, and what is
        still UNTESTED. Surface this at each phase checkpoint and at session end.

        Args:
            domain: target in .burp-intel/<domain>/.
            standards: subset of owasp_top10 / api_top10 / wstg (default: all three).
        """
        stds = standards or ["owasp_top10", "api_top10", "wstg"]
        findings = load_intel(domain, "findings").get("findings", [])
        tested = _tested_classes(domain)
        heatmaps = [build_heatmap(s, tested, findings)
                    for s in stds if s in STANDARDS]
        if not heatmaps:
            return (f"No valid standard in {stds}; "
                    f"valid: {sorted(STANDARDS.keys())}")
        return render_coverage_status(domain, heatmaps)

    @mcp.tool()
    async def standards_coverage(domain: str, standard: str = "owasp_top10") -> dict:
        """Coverage heatmap of a target against a security standard's checklist.

        Shows every category of the standard as tested / has-findings / untested
        — the "what did we NOT test" assurance view, not just filed findings.

        Args:
            domain: target in .burp-intel/<domain>/.
            standard: one of owasp_top10, api_top10, wstg.

        Returns: {standard, coverage_pct, categories:{id:{name,tested,findings,status}}}.
        """
        if standard not in STANDARDS:
            return {
                "error": f"unknown standard '{standard}'",
                "valid": sorted(STANDARDS.keys()),
            }
        findings = load_intel(domain, "findings").get("findings", [])
        return build_heatmap(standard, _tested_classes(domain), findings)
