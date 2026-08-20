"""MCP tools: BloodHound / certipy attack-path edges -> operator log + Ghostwriter.

  ingest_bloodhound            - parse a collection, record high-value edges on
                                 the network operator log (ATT&CK-tagged). Offline;
                                 useful even without Ghostwriter.
  sync_bloodhound_to_ghostwriter - ingest, then forward BOTH lanes to Ghostwriter:
                                 the edges as oplog timeline entries AND as
                                 reportedFindings on the report. Idempotent.

The network lane is Burp-blind, so evidence for AD attack paths is the operator
log (op ids) + Ghostwriter, never a Burp logger_index.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import _bloodhound, _ghostwriter
from ._oplog import record_action


def _ingested_path(domain: str) -> Path:
    from praetor.tools.workspace import ensure_workspace
    return ensure_workspace(domain)["network"] / "_bloodhound_ingested.json"


def _load_ingested(domain: str) -> dict:
    p = _ingested_path(domain)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_ingested(domain: str, m: dict) -> None:
    p = _ingested_path(domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(m), encoding="utf-8")


def _finding_id(edge: dict) -> str:
    sig = _bloodhound.edge_signature(edge)
    return "bh-" + hashlib.sha256(sig.encode("utf-8")).hexdigest()[:10]


def _ingest(domain: str, path: str, source_host: str) -> tuple[list[dict], dict]:
    """Parse edges and record any not-yet-recorded ones on the operator log.
    Returns (edges, sig->oplog_id map). Re-runs reuse existing op ids."""
    edges = _bloodhound.extract_edges(path)
    recorded = _load_ingested(domain)
    for edge in edges:
        sig = _bloodhound.edge_signature(edge)
        if sig in recorded:
            continue
        op_id = record_action(
            domain, "bloodhound", edge.get("abuse", ""),
            description=_bloodhound.edge_title(edge),
            source=source_host, target=str(edge.get("target", "")),
            output=edge.get("why", ""), user_context=str(edge.get("principal", "")),
            tactic=edge.get("tactic", ""), technique=edge.get("technique", ""),
            tags=[f"bh:{edge.get('kind')}", f"sev:{edge.get('severity')}"],
        )
        recorded[sig] = op_id
    _save_ingested(domain, recorded)
    return edges, recorded


def _summary(edges: list[dict]) -> list[str]:
    from collections import Counter
    by_kind = Counter(e["kind"] for e in edges)
    by_sev = Counter(e["severity"] for e in edges)
    lines = [f"  edges: {len(edges)} "
             f"({', '.join(f'{k}={v}' for k, v in by_kind.items())})",
             f"  severity: {', '.join(f'{k}={v}' for k, v in by_sev.items())}"]
    crit = [e for e in edges if e["severity"] in ("critical", "high")][:12]
    if crit:
        lines.append("  top edges:")
        for e in crit:
            lines.append(f"    [{e['severity']}] {_bloodhound.edge_title(e)}")
    return lines


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def ingest_bloodhound(domain: str, path: str, source_host: str = "") -> str:
        """Parse a BloodHound collection / certipy JSON into high-value AD edges
        and record them on the network operator log (ATT&CK-tagged).

        Args:
            domain: engagement key.
            path: a BloodHound .zip, a directory of *.json, a single *.json, or a
                certipy `find -json` file. Extracts dangerous ACLs
                (ForceChangePassword / GenericAll / WriteDacl / AddKeyCredentialLink /
                AddMember), DCSync rights, and AD CS ESC1-16 templates.
            source_host: DC / collector host (recorded as the operator-log source).

        Offline (no target traffic). Idempotent — already-recorded edges are
        reused, not duplicated. Forward to Ghostwriter with
        sync_bloodhound_to_ghostwriter.
        """
        edges, recorded = _ingest(domain, path, source_host)
        if not edges:
            return (f"ingest_bloodhound: no high-value edges parsed from {path!r}. "
                    "Expected a BloodHound collection (.zip/dir/*.json) or certipy find -json.")
        op_ids = [recorded[_bloodhound.edge_signature(e)] for e in edges]
        lines = [f"ingest_bloodhound({domain}): recorded to operator log "
                 f"[{op_ids[0]}..{op_ids[-1]}]"]
        lines += _summary(edges)
        lines.append("  next: sync_bloodhound_to_ghostwriter(domain, path) to forward timeline + findings")
        return "\n".join(lines)

    @mcp.tool()
    async def sync_bloodhound_to_ghostwriter(domain: str, path: str, source_host: str = "") -> str:
        """Ingest a BloodHound / certipy collection and forward it to Ghostwriter
        on BOTH lanes: the attack-path edges as oplog timeline entries AND as
        reportedFindings attached to the report.

        Args:
            domain: engagement key.
            path: BloodHound .zip / dir / *.json, or certipy find -json.
            source_host: DC / collector host (operator-log source).

        Idempotent — per-domain markers skip already-forwarded entries. If
        Ghostwriter is unset, the edges are still recorded on the local operator
        log (run ghostwriter_status for config).
        """
        edges, recorded = _ingest(domain, path, source_host)
        if not edges:
            return (f"sync_bloodhound_to_ghostwriter: no edges parsed from {path!r}. "
                    "Expected a BloodHound collection or certipy find -json.")

        if not _ghostwriter.is_configured():
            op_ids = [recorded[_bloodhound.edge_signature(e)] for e in edges]
            lines = [f"sync_bloodhound_to_ghostwriter({domain}): Ghostwriter NOT configured "
                     f"({_ghostwriter.config_hint()}).",
                     f"  {len(edges)} edges recorded on the local operator log [{op_ids[0]}..{op_ids[-1]}].",
                     "  set GHOSTWRITER_URL / token / oplog id, then re-run to forward."]
            lines += _summary(edges)
            return "\n".join(lines)

        # Lane 1: timeline — forward the operator-log entries (BH ops included).
        op_res = await _ghostwriter.sync(domain, what="oplog")
        # Lane 2: findings — forward the edges as reportedFindings.
        findings = []
        for e in edges:
            f = _bloodhound.edge_to_finding(e, recorded.get(_bloodhound.edge_signature(e), ""))
            f["id"] = _finding_id(e)
            findings.append(f)
        fnd_res = await _ghostwriter.sync_bloodhound_findings(domain, findings)

        lines = [f"sync_bloodhound_to_ghostwriter({domain}) -> {__gw_url()}"]
        lines += _summary(edges)
        if "error" in op_res:
            lines.append(f"  timeline: SKIPPED ({op_res['error']})")
        else:
            lines.append(f"  timeline: +{op_res['pushed']['oplog']} oplog entries forwarded")
        if "error" in fnd_res:
            lines.append(f"  findings: SKIPPED ({fnd_res['error']})")
        else:
            lines.append(f"  findings: +{fnd_res['pushed']} reportedFindings "
                         f"({fnd_res.get('skipped', 0)} already synced)")
            for e in (op_res.get("errors", []) + fnd_res.get("errors", []))[:5]:
                lines.append(f"    error: {e}")
        return "\n".join(lines)


def __gw_url() -> str:
    from praetor import config
    return config.GHOSTWRITER_URL or "(unset)"
