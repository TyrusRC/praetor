"""Human-readable per-finding markdown, projected from the canonical findings.json record.

findings.json stays the source of truth; these files are regenerated, never read back.
"""
import json
import shutil

from praetor.tools.workspace import workspace_paths


def render_finding_md(finding: dict) -> str:
    """Render the working writeup for one finding.

    Every section here is projected from a field that actually exists on the
    record. Sections whose source field is empty are omitted rather than
    emitted as an empty heading — an empty "## PoC Steps" under a finding that
    has none reads as a claim that steps were captured, and that mismatch
    between the writeup and the record is exactly what makes these files
    untrustworthy.
    """
    fid = finding.get("id", "UNKNOWN")
    lines = [
        f"# {fid} — {finding.get('title', '(untitled)')}",
        "",
        f"- **Severity:** {finding.get('severity', 'n/a')}",
        f"- **Status:** {finding.get('status', 'suspected')}",
        f"- **Vuln type:** {finding.get('vuln_type', '') or 'n/a'}",
        f"- **Endpoint:** {finding.get('endpoint', '')}",
        f"- **Parameter:** {finding.get('parameter', '')}",
    ]
    conf = finding.get("confidence")
    if isinstance(conf, (int, float)):
        lines.append(f"- **Confidence:** {conf:.2f}")
    cvss = finding.get("cvss4_vector") or ""
    if cvss:
        band = finding.get("cvss4_severity") or ""
        suffix = f" (scores {band})" if band else ""
        lines.append(f"- **CVSS 4.0:** `{cvss}`{suffix}")
    if finding.get("cwe"):
        lines.append(f"- **CWE:** {finding['cwe']}")
    lines.append("")

    desc = (finding.get("description") or "").strip()
    if desc:
        lines += ["## Description", desc, ""]

    impact = (finding.get("impact") or "").strip()
    if impact:
        lines += ["## Impact", impact, ""]

    evidence = finding.get("evidence") or {}
    if evidence:
        lines += [
            "## Evidence",
            "",
            "> Indices below are references into THIS Burp session only. They are"
            " operator bookkeeping — never paste them into a report or a"
            " submission; cite the request/response instead.",
            "",
            "```json",
            json.dumps(evidence, indent=2, default=str),
            "```",
            "",
        ]

    evidence_text = (finding.get("evidence_text") or "").strip()
    if evidence_text:
        lines += ["## Proof", "```", evidence_text, "```", ""]

    reproductions = finding.get("reproductions") or []
    if reproductions:
        lines.append("## Reproductions")
        for r in reproductions:
            lines.append(f"- {r}")
        lines.append("")

    poc_request = (finding.get("poc_request") or "").strip()
    if poc_request:
        lines += ["## PoC Request", "```http", poc_request, "```", ""]

    poc_steps = finding.get("reproduction_steps") or finding.get("poc_steps") or []
    if poc_steps:
        lines.append("## PoC Steps")
        for i, step in enumerate(poc_steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    remediation = (finding.get("remediation") or "").strip()
    if remediation:
        lines += ["## Remediation", remediation, ""]

    # Only annotations Burp confirmed storing. The text here is the read-back,
    # never what the annotate call requested — citing the requested text is how
    # a writeup ends up describing a Burp comment that the history does not have.
    annotations = [a for a in (finding.get("annotations") or []) if isinstance(a, dict)]
    if annotations:
        lines.append("## Burp Annotations (read back from the live history)")
        for a in annotations:
            entry = f" — {a.get('method', '')} {a.get('url', '')}".rstrip()
            lines.append(
                f"- #{a.get('index', '?')} [{a.get('color', 'NONE')}] "
                f"{a.get('comment') or '(no comment)'}{entry if entry.strip('— ') else ''}"
            )
        lines.append("")

    chain = finding.get("chain_with") or []
    if chain:
        lines += ["", "## Chained With", *[f"- {c}" for c in chain]]
    retests = finding.get("retests") or []
    if retests:
        lines += ["", "## Retest History"]
        for rt in retests:
            lines.append(
                f"- v{rt.get('version')} {rt.get('date')} — "
                f"{rt.get('status')}: {rt.get('notes', '')}"
            )
    return "\n".join(lines) + "\n"


def _finding_dir(domain: str, finding_id: str):
    return workspace_paths(domain)["findings"] / finding_id


def write_finding_projection(domain: str, finding: dict) -> None:
    """Best-effort: never raise into the caller's save path."""
    try:
        fid = finding.get("id")
        if not fid:
            return
        d = _finding_dir(domain, fid)
        d.mkdir(parents=True, exist_ok=True)
        (d / "current.md").write_text(render_finding_md(finding), encoding="utf-8")
    except Exception:
        pass  # projection is advisory; findings.json is authoritative


def remove_finding_projection(domain: str, finding_id: str) -> None:
    try:
        d = _finding_dir(domain, finding_id)
        if d.exists():
            shutil.rmtree(d)
    except Exception:
        pass
