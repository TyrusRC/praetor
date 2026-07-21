"""SARIF 2.1.0 exporter for saved findings.

SARIF = Static Analysis Results Interchange Format. Consumed by GitHub Advanced
Security (Code Scanning), GitLab SAST dashboards, Azure DevOps, Sonarqube, and
most CI security gates. Lets a DAST finding from Praetor surface in the same
PR-comment / branch-protection workflow the team already uses for SAST.

Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._framework_map import attack_tag_list, framework_tags

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

_COMPLIANCE_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "compliance_mappings.json"
)


def _load_compliance() -> dict[str, Any]:
    try:
        return json.loads(_COMPLIANCE_PATH.read_text(encoding="utf-8")).get("mappings", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _vuln_tags(vuln_type: str, mappings: dict) -> list[str]:
    if not vuln_type:
        return []
    entry = mappings.get(vuln_type.lower())
    if not entry:
        return []
    tags: list[str] = []
    for fw, ids in entry.items():
        if isinstance(ids, list):
            tags.extend(f"{fw}:{i}" for i in ids)
    return tags


def _to_sarif_result(f: dict, mappings: dict) -> dict:
    sev = str(f.get("severity") or "INFO").upper()
    vuln = (f.get("vuln_type") or "unknown").lower()
    endpoint = f.get("endpoint") or ""
    title = f.get("title") or vuln.upper()
    desc = f.get("description") or ""
    evidence_text = f.get("evidence_text") or ""

    fw = framework_tags(vuln)
    properties: dict[str, Any] = {
        "severity": sev,
        "vuln_type": vuln,
        "status": f.get("status") or "suspected",
        "compliance": _vuln_tags(vuln, mappings),
        # Framework tagging (W34-b): MITRE ATT&CK / WSTG / CWE.
        "attack": fw["attack_ck"],
        "wstg": fw["wstg"],
        "cwe": fw["cwe"] or (f.get("cwe") or ""),
        "owasp": fw["owasp"],
        "tags": _vuln_tags(vuln, mappings) + attack_tag_list(vuln),
    }
    if evidence := f.get("evidence"):
        if isinstance(evidence, dict):
            if li := evidence.get("logger_index"):
                properties["logger_index"] = li
            if pi := evidence.get("proxy_history_index"):
                properties["proxy_history_index"] = pi
            if ci := evidence.get("collaborator_interaction_id"):
                properties["collaborator_interaction_id"] = ci

    return {
        "ruleId": f"praetor.{vuln}",
        "level": _SEVERITY_TO_LEVEL.get(sev, "warning"),
        "message": {"text": f"{title}\n\n{desc}\n\nEvidence: {evidence_text}".strip()},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": endpoint or "unknown"},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": properties,
    }


def _to_sarif(findings: list[dict]) -> dict:
    mappings = _load_compliance()

    rule_ids: dict[str, dict] = {}
    for f in findings:
        vuln = (f.get("vuln_type") or "unknown").lower()
        rid = f"praetor.{vuln}"
        if rid not in rule_ids:
            tags = _vuln_tags(vuln, mappings)
            fw_tags = attack_tag_list(vuln)
            all_tags = tags + fw_tags
            rule_ids[rid] = {
                "id": rid,
                "name": vuln,
                "shortDescription": {"text": vuln.replace("_", " ").title()},
                "fullDescription": {
                    "text": f"Praetor DAST finding category: {vuln}. Compliance: {', '.join(tags) if tags else 'none mapped'}."
                },
                "properties": {"tags": all_tags or [vuln]},
            }

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Praetor",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/TyrusRC/praetor",
                        "rules": list(rule_ids.values()),
                    }
                },
                "results": [_to_sarif_result(f, mappings) for f in findings],
            }
        ],
    }


def register(mcp: FastMCP):

    @mcp.tool()
    async def export_sarif(endpoint: str = "", confirmed_only: bool = True) -> str:
        """Export saved findings as SARIF 2.1.0 JSON (GitHub Code Scanning / CI-gate compatible).

        Args:
            endpoint: Optional URL substring filter
            confirmed_only: If True, exclude suspected / likely_false_positive / stale
        """
        params: dict[str, str] = {}
        if endpoint:
            params["endpoint"] = endpoint
        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        findings = data.get("findings", []) or []
        if confirmed_only:
            findings = [f for f in findings if str(f.get("status") or "").lower() == "confirmed"]

        return json.dumps(_to_sarif(findings), indent=2, default=str)
