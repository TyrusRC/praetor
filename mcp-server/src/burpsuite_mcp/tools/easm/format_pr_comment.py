"""format_pr_comment — render a finding as inline PR-comment markdown.

Output suitable for GitHub / GitLab / Bitbucket PR review tools. Includes
severity badge, evidence summary, curl repro, and remediation pointer.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import (
    _find_by_id,
    _load_findings_file,
    _safe_findings_path,
)


_SEVERITY_BADGE = {
    "CRITICAL": "![critical](https://img.shields.io/badge/-CRITICAL-red)",
    "HIGH":     "![high](https://img.shields.io/badge/-HIGH-orange)",
    "MEDIUM":   "![medium](https://img.shields.io/badge/-MEDIUM-yellow)",
    "LOW":      "![low](https://img.shields.io/badge/-LOW-lightgrey)",
    "INFO":     "![info](https://img.shields.io/badge/-INFO-lightblue)",
}


def _curl_repro(f: dict) -> str:
    ev = f.get("evidence") or {}
    method = (f.get("method") or ev.get("method") or "GET").upper()
    url = ev.get("url") or f.get("endpoint") or ""
    body = ev.get("body") or ""
    parts = [f"curl -i -X {method} \\"]
    parts.append("  -x http://127.0.0.1:8080 \\")
    headers = ev.get("request_headers") or []
    for h in headers[:8]:
        if isinstance(h, dict):
            n, v = h.get("name", ""), h.get("value", "")
        else:
            n, v = (h.split(":", 1) + [""])[:2]
        if n and v:
            parts.append(f"  -H '{n}: {v}' \\")
    if body:
        clip = body if len(body) < 300 else body[:300] + "..."
        parts.append(f"  --data {clip!r} \\")
    parts.append(f"  '{url}'")
    return "\n".join(parts)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def format_pr_comment(finding_id: str, domain: str = "") -> str:
        """Render a saved finding as inline PR-comment markdown.

        Args:
            finding_id: persistent finding ID.
            domain: optional explicit domain. Auto-resolved if omitted.
        """
        if not domain:
            try:
                base = _safe_findings_path("")
                root = base.parent
            except Exception:
                root = None
            if root is not None and root.exists():
                for child in root.iterdir():
                    p = child / "findings.json"
                    if p.exists() and _find_by_id(_load_findings_file(p), finding_id)[1]:
                        domain = child.name
                        break
        if not domain:
            return f"Error: finding {finding_id!r} not found."

        findings = _load_findings_file(_safe_findings_path(domain))
        _, f = _find_by_id(findings, finding_id)
        if f is None:
            return f"Error: finding {finding_id!r} not found in {domain!r}."

        sev = (f.get("severity") or "INFO").upper()
        badge = _SEVERITY_BADGE.get(sev, sev)
        title = f.get("title") or f.get("vuln_type") or "Finding"
        endpoint = f.get("endpoint") or ""
        param = f.get("parameter") or ""
        cwe = ", ".join(
            t for t in (f.get("compliance") or {}).get("cwe", []) if t
        ) or "n/a"

        out = [
            f"### {badge}  {title}",
            "",
            f"**Endpoint:** `{endpoint}`",
            f"**Parameter:** `{param or '(none)'}`",
            f"**Vuln class:** `{f.get('vuln_type','?')}`",
            f"**CWE:** {cwe}",
            f"**Finding ID:** `{finding_id}`",
            "",
            "#### Evidence",
            "```",
            (f.get("evidence_text") or "(no inline evidence text)")[:1500],
            "```",
            "",
            "#### Reproduction",
            "```bash",
            _curl_repro(f),
            "```",
            "",
            "#### Next",
            f"- Run `explore_issue({finding_id!r})` for class-specific follow-up probes.",
            f"- Run `explain_finding({finding_id!r})` for chain candidates.",
        ]
        return "\n".join(out)
