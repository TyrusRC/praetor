"""Evidence-flow tools: one-call curation + history-noise audit.
Burp history is read-only (Montoya) — these curate and audit, never delete."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.notes._helpers import (
    _load_findings_file, _safe_findings_path, _write_findings_file,
)

from . import _audit, _curate


async def curate_evidence(finding_id: str, index: int, domain: str,
                          color: str = "RED", comment: str = "",
                          endpoint: str = "") -> str:
    """Curate one evidence request in a single call: annotate it in Burp,
    send it to the Organizer, and record it as the finding's canonical evidence
    index (Rule 18). Use after a finding is confirmed."""
    ann = await client.post("/api/annotations/set", json={
        "index": index, "color": color,
        "comment": comment or f"{finding_id} | evidence", "endpoint": endpoint})
    if isinstance(ann, dict) and "error" in ann:
        return f"Annotation failed: {ann['error']}"
    org = await client.post("/api/organizer/send", json={"index": index})
    org_note = org.get("error", "sent") if isinstance(org, dict) else "sent"

    path = _safe_findings_path(domain)
    findings = _load_findings_file(path)
    findings, msg = _curate.apply_curation(findings, finding_id, index, color)
    if "not found" not in msg:
        _write_findings_file(path, findings)
    return f"{msg} Annotated {color} + organizer:{org_note}."


async def audit_history_noise(domain: str = "", limit: int = 1000) -> dict:
    """Report proxy-history composition (in-scope / static / duplicates / noisy
    hosts) and recommendations. Burp cannot delete history — this guides
    capture-time scope + off-proxy routing to keep the .burp project lean."""
    params = {"limit": limit}
    if domain:
        params["host"] = domain
    data = await client.get("/api/proxy/history", params=params)
    if isinstance(data, dict) and "error" in data:
        return {"error": data["error"]}
    entries = data.get("history", data) if isinstance(data, dict) else data
    scope = {domain} if domain else None
    return _audit.analyze_noise(entries if isinstance(entries, list) else [], scope)


def register(mcp: FastMCP) -> None:
    mcp.tool()(curate_evidence)
    mcp.tool()(audit_history_noise)
