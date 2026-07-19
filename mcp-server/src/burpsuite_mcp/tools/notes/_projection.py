"""Human-readable per-finding markdown, projected from the canonical findings.json record.

findings.json stays the source of truth; these files are regenerated, never read back.
"""
import json
import shutil

from burpsuite_mcp.tools.workspace import workspace_paths


def render_finding_md(finding: dict) -> str:
    fid = finding.get("id", "UNKNOWN")
    lines = [
        f"# {fid} — {finding.get('title', '(untitled)')}",
        "",
        f"- **Severity:** {finding.get('severity', 'n/a')}",
        f"- **Status:** {finding.get('status', 'suspected')}",
        f"- **Endpoint:** {finding.get('endpoint', '')}",
        f"- **Parameter:** {finding.get('parameter', '')}",
        "",
        "## Evidence",
        "```json",
        json.dumps(finding.get("evidence", {}), indent=2, default=str),
        "```",
        "",
        "## Reproductions",
    ]
    for r in finding.get("reproductions", []) or []:
        lines.append(f"- {r}")
    lines += ["", "## PoC Steps"]
    for i, step in enumerate(finding.get("poc_steps", []) or [], 1):
        lines.append(f"{i}. {step}")
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
        (d / "current.md").write_text(render_finding_md(finding))
    except Exception:
        pass  # projection is advisory; findings.json is authoritative


def remove_finding_projection(domain: str, finding_id: str) -> None:
    try:
        d = _finding_dir(domain, finding_id)
        if d.exists():
            shutil.rmtree(d)
    except Exception:
        pass
