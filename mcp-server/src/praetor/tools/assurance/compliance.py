"""generate_compliance_report — findings grouped by a compliance framework.

Reuses data/compliance_mappings.json (vuln_type -> control codes) to render
confirmed findings under the controls they implicate for a named standard
(PCI-DSS v4, SOC 2, HIPAA, GDPR, OWASP). Only confirmed findings count —
same true-positives-only rule as generate_report.

`build_compliance_rollup` is pure; `generate_compliance_report` is the tool.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .._vuln_class import canonical
from ..report.lifecycle import load_intel
from ._standards import _compliance, STANDARDS

# Frameworks whose control codes live in compliance_mappings.json, plus the
# heatmap standards that resolve through category_of. Human names for headers.
_FRAMEWORKS: dict[str, str] = {
    "pci_dss_v4": "PCI-DSS v4.0",
    "soc2_t2": "SOC 2 Type II",
    "hipaa": "HIPAA Security Rule",
    "gdpr": "GDPR (EU) 2016/679",
    "owasp": "OWASP Top 10 (2021)",
}

_CONFIRMED = {"confirmed"}


def build_compliance_rollup(standard: str, findings: list[dict]) -> dict[str, Any]:
    """Group confirmed findings by the control codes they implicate.

    Raises KeyError for an unknown framework.
    """
    if standard not in _FRAMEWORKS:
        raise KeyError(standard)

    mappings = _compliance()
    controls: dict[str, dict[str, Any]] = {}
    counted = 0

    for f in findings:
        if f.get("status") not in _CONFIRMED:
            continue
        cls = canonical(f.get("vuln_type", ""))
        codes = (mappings.get(cls) or {}).get(standard, []) or []
        if not codes:
            continue
        counted += 1
        for code in codes:
            slot = controls.setdefault(code, {"count": 0, "findings": []})
            slot["count"] += 1
            slot["findings"].append(
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "endpoint": f.get("endpoint", ""),
                    "vuln_type": cls,
                }
            )

    return {
        "standard": standard,
        "standard_name": _FRAMEWORKS[standard],
        "total_findings": counted,
        "controls": controls,
    }


def _render_markdown(roll: dict[str, Any]) -> str:
    lines = [
        f"# Compliance report — {roll['standard_name']}",
        "",
        f"Confirmed findings mapped to controls: **{roll['total_findings']}**",
        "",
    ]
    if not roll["controls"]:
        lines.append("_No confirmed findings map to this framework._")
        return "\n".join(lines)
    for code in sorted(roll["controls"]):
        slot = roll["controls"][code]
        lines.append(f"## {code} — {slot['count']} finding(s)")
        for fnd in slot["findings"]:
            sev = str(fnd["severity"]).upper()
            ep = f" — `{fnd['endpoint']}`" if fnd["endpoint"] else ""
            lines.append(f"- **[{sev}]** {fnd['title']}{ep}")
        lines.append("")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def generate_compliance_report(
        domain: str, standard: str = "pci_dss_v4"
    ) -> dict:
        """Confirmed findings grouped by a compliance framework's controls.

        Frameworks: pci_dss_v4, soc2_t2, hipaa, gdpr, owasp. Only confirmed
        findings are included (true-positives-only). Writes markdown under
        reports/ and returns the rollup.
        """
        if standard not in _FRAMEWORKS:
            return {"error": f"unknown framework '{standard}'", "valid": sorted(_FRAMEWORKS)}
        findings = load_intel(domain, "findings").get("findings", [])
        roll = build_compliance_rollup(standard, findings)

        from pathlib import Path

        out = Path(".burp-intel") / domain / "reports" / f"compliance-{standard}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_render_markdown(roll), encoding="utf-8")
        roll["path"] = str(out)
        return roll
