"""review_finding_for_submission — pre-submission triager simulator (W7, T2).

Senior-engineer move: assess_finding is a *gate*; this is a *review*.
The gate stops obvious problems; the review surfaces what a real human triager
would push back on:

  - Inflated severity (Reflected XSS = critical? No.)
  - Weak impact phrasing ("could lead to" / "may allow")
  - Repro clarity (missing baseline, no curl command in evidence)
  - Victim-action absurdity (self-XSS, devtools paste)
  - Chain explicit (NEVER_SUBMIT alone vs chain_with[])
  - Slop indicators (vague description, AI-template smell)
  - Status hygiene (still suspected vs confirmed)

Returns:
    {
      ready_to_submit: bool,
      blockers: [str],     # MUST fix before submit
      suggestions: [str],  # SHOULD fix to maximise payout
      detected_smells: [str],  # observed slop patterns
    }

Used by the operator before `generate_report` or platform-specific export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._helpers import _safe_findings_path


_INFLATION_CAP = {
    "open_redirect": "medium",
    "self_xss": "low",
    "reflected_xss": "high",
    "info_disclosure": "low",
    "verbose_error": "low",
    "stack_trace": "low",
    "version_disclosure": "low",
    "missing_security_header": "low",
    "rate_limit": "low",
    "clickjacking": "low",
    "csrf_logout": "low",
    "mixed_content": "low",
    "username_enumeration": "low",
    "email_enumeration": "low",
}

_NEVER_SUBMIT_ALONE = {
    "missing_security_header", "csrf_logout", "open_redirect_alone",
    "self_xss", "clickjacking", "rate_limit", "stack_trace",
    "username_enumeration", "email_enumeration", "version_disclosure",
    "mixed_content", "referrer_policy", "spf", "dmarc", "dkim",
    "host_header_no_cache", "cors_no_credentials", "ssl_config",
    "reverse_tabnabbing", "idn_homograph", "autocomplete_off",
    "options_enabled", "content_spoofing",
}

_SLOP_PHRASES = [
    "could lead to",
    "may allow",
    "potentially allows",
    "this might be exploited",
    "could be exploited",
    "in theory",
    "appears to be vulnerable",
    "seems to allow",
    "may be exploitable",
]

_AI_TEMPLATE_SMELLS = [
    "as an ai language model",
    "i hope this helps",
    "in conclusion",
    "to summarize",
    "i would recommend",
    "based on the analysis",
]


def _find_finding(domain: str, finding_id: str) -> tuple[dict | None, Path]:
    path = _safe_findings_path(domain)
    if not path.exists():
        return None, path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None, path
    items = data if isinstance(data, list) else data.get("findings", [])
    for f in items:
        fid = f.get("id") or f.get("finding_id")
        if fid == finding_id:
            return f, path
    return None, path


def _check_severity_inflation(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    vt = str(finding.get("vuln_type") or "").lower()
    sev = str(finding.get("severity") or "").lower()
    cap = _INFLATION_CAP.get(vt)
    if not cap:
        return
    order = ["info", "low", "medium", "high", "critical"]
    try:
        if order.index(sev) > order.index(cap):
            blockers.append(
                f"severity inflated: {vt} capped at {cap}, you have {sev}. Triager will downgrade."
            )
    except ValueError:
        pass


def _check_impact_phrasing(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    description = " ".join([
        str(finding.get("description") or ""),
        str(finding.get("impact") or ""),
        str(finding.get("evidence", {}).get("summary") or ""),
    ]).lower()
    hits = [p for p in _SLOP_PHRASES if p in description]
    if hits:
        blockers.append(
            f"weak impact phrasing detected ({', '.join(hits[:3])}). "
            f"Rewrite in concrete attacker terms: 'attacker reads X', not 'could lead to X'."
        )
    if not finding.get("impact") and not finding.get("description"):
        blockers.append("no impact / description field — triager has no business-impact framing")


def _check_repro_clarity(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    evidence = finding.get("evidence") or {}
    has_index = any(evidence.get(k) for k in ("logger_index", "proxy_history_index", "collaborator_interaction_id"))
    if not has_index:
        blockers.append("no Burp index in evidence — repro is not anchorable to captured traffic")
    if not finding.get("endpoint"):
        blockers.append("no endpoint field — triager cannot identify the URL")
    if not evidence.get("baseline_status") and not evidence.get("baseline"):
        suggestions.append("include baseline_status / baseline_length so the delta is provable")
    vt = str(finding.get("vuln_type") or "").lower()
    if vt in ("sqli_time", "sqli_blind", "ssrf_blind", "race_condition", "request_smuggling"):
        reps = evidence.get("reproductions") or []
        if len(reps) < 3:
            blockers.append(
                f"{vt} requires reproductions[] >= 3 (Rule 10a). Got {len(reps)}."
            )


def _check_never_submit_alone(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    vt = str(finding.get("vuln_type") or "").lower()
    chain = finding.get("chain_with") or []
    if vt in _NEVER_SUBMIT_ALONE and not chain:
        blockers.append(
            f"vuln_type '{vt}' is NEVER_SUBMIT alone — supply chain_with[<anchor_id>] referencing a confirmed finding"
        )


def _check_victim_action(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    desc = " ".join([
        str(finding.get("description") or ""),
        str(finding.get("repro_steps") or ""),
    ]).lower()
    absurd = ["paste in devtools", "paste in console", "user pastes", "user enters payload",
              "user types <script", "victim runs"]
    for phrase in absurd:
        if phrase in desc:
            blockers.append(f"absurd-victim-action smell: '{phrase}'. Self-attack does not count.")
            return


def _check_status(finding: dict, blockers: list[str], suggestions: list[str]) -> None:
    status = str(finding.get("status") or "").lower()
    if status == "suspected":
        blockers.append("status=suspected — promote to confirmed via verify-finding.md replay first")
    elif status in ("stale", "likely_false_positive"):
        blockers.append(f"status={status} — do not submit; re-verify or delete")


def _detect_ai_smells(finding: dict, smells: list[str]) -> None:
    body = " ".join([
        str(finding.get("description") or ""),
        str(finding.get("impact") or ""),
        str(finding.get("remediation") or ""),
    ]).lower()
    for s in _AI_TEMPLATE_SMELLS:
        if s in body:
            smells.append(f"ai-template phrasing: '{s}' — rewrite in operator voice")


def _check_cvss(finding: dict, suggestions: list[str]) -> None:
    cvss = finding.get("cvss") or finding.get("cvss_vector") or finding.get("cvss4_vector")
    if not cvss:
        suggestions.append("no CVSS vector — add cvss / cvss_vector / cvss4_vector for triager scoring transparency")


def register(mcp: FastMCP):

    @mcp.tool()
    async def review_finding_for_submission(
        domain: str,
        finding_id: str,
    ) -> dict:
        """Simulate a triager's pushback BEFORE you hit submit. The pre-submission slop guard.

        Reads the finding from .burp-intel/<domain>/findings.json. Runs 8 checks:
          1. severity inflation (capped per NEVER_SUBMIT table)
          2. weak impact phrasing ('could lead to', 'may allow')
          3. repro clarity (Burp index + baseline + reproductions for timing)
          4. NEVER_SUBMIT alone (Rule 17 — must chain_with)
          5. absurd victim action (self-XSS / devtools paste)
          6. status hygiene (no suspected / stale / FP submissions)
          7. AI-template smells (slop indicators)
          8. CVSS vector presence

        Returns: ready_to_submit + blockers (MUST fix) + suggestions (SHOULD fix) + detected_smells.
        """
        finding, path = _find_finding(domain, finding_id)
        if finding is None:
            return {
                "error": f"finding {finding_id!r} not found in {path}",
                "ready_to_submit": False,
            }

        blockers: list[str] = []
        suggestions: list[str] = []
        smells: list[str] = []

        _check_status(finding, blockers, suggestions)
        _check_severity_inflation(finding, blockers, suggestions)
        _check_impact_phrasing(finding, blockers, suggestions)
        _check_repro_clarity(finding, blockers, suggestions)
        _check_never_submit_alone(finding, blockers, suggestions)
        _check_victim_action(finding, blockers, suggestions)
        _check_cvss(finding, suggestions)
        _detect_ai_smells(finding, smells)

        return {
            "finding_id": finding_id,
            "vuln_type": finding.get("vuln_type"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "ready_to_submit": not blockers,
            "blockers": blockers,
            "suggestions": suggestions,
            "detected_smells": smells,
        }
