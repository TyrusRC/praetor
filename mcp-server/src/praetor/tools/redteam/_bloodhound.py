"""Parse BloodHound (legacy + CE) collection output and certipy JSON into
high-value AD attack-path edges — the input to the Ghostwriter forwarder.

BloodHound / SharpHound / bloodhound-python emit per-node JSON (users, groups,
computers, domains, ...) each carrying an `Aces` list of ACL edges. certipy
`find -json` emits per-template `[!] Vulnerabilities` (ESC1-16). We do NOT run a
graph engine — we extract the dangerous edges that are directly present in the
collected objects (the ones that unravel a domain: ForceChangePassword,
GenericAll, WriteDacl, AddKeyCredentialLink, DCSync, AD CS ESC). That covers the
DanglingTree-class chain (alex.o -ForceChangePassword-> jake.h -ESC-> Administrator)
without a Neo4j round-trip.

Accepts a .zip, a directory of *.json, or a single *.json.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

# ACL right -> (severity, ATT&CK tactic, technique, technique_name, abuse hint).
# The abuse hint is a runnable primitive with <placeholders> for the operator.

from ._bh_extract import (
    _norm,
    _iter_docs,
    _sid_name_map,
    _doc_type,
    _extract_acl_edges,
    _extract_certipy_esc,
    _extract_trusts,
    _extract_delegation,
    _ACL_RIGHTS,
    _DCSYNC_RIGHTS,
    _TRUST_DIR,
)

def extract_edges(path: str) -> list[dict]:
    """Parse a BloodHound collection and/or certipy JSON at `path` into edges.
    Each edge: {kind, principal, right, target, severity, tactic, technique,
    technique_name, abuse, [why]}. Empty list on unreadable/empty input.
    Edge kinds: acl, dcsync, adcs_esc, trust, delegation.
    """
    docs = [d for d in _iter_docs(path) if isinstance(d, dict)]
    if not docs:
        return []
    sid2name = _sid_name_map(docs)
    edges = _extract_acl_edges(docs, sid2name)
    edges.extend(_extract_certipy_esc(docs))
    edges.extend(_extract_trusts(docs))
    edges.extend(_extract_delegation(docs, sid2name))
    # crown jewels first
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    edges.sort(key=lambda e: order.get(e.get("severity"), 9))
    return edges


def edge_signature(edge: dict) -> str:
    return f"{edge.get('kind')}|{edge.get('principal')}|{_norm(edge.get('right'))}|{edge.get('target')}"


def edge_title(edge: dict) -> str:
    if edge["kind"] == "adcs_esc":
        return f"AD CS {edge['right']} — vulnerable template {edge['target']}"
    if edge["kind"] == "dcsync":
        return f"DCSync rights: {edge['principal']} can replicate {edge['target']}"
    if edge["kind"] == "trust":
        return f"Domain trust: {edge['principal']} <-> {edge['target']} ({edge['right']})"
    if edge["kind"] == "delegation":
        return f"Kerberos delegation: {edge['principal']} has {edge['right']}"
    return f"AD ACL abuse: {edge['principal']} --{edge['right']}--> {edge['target']}"


def edge_to_finding(edge: dict, oplog_id: str = "") -> dict:
    """Shape an edge as a Praetor finding dict (consumed by map_reported_finding)."""
    kind = edge["kind"]
    vuln_type = {"adcs_esc": "adcs_esc", "dcsync": "dcsync",
                 "trust": "ad_trust_abuse", "delegation": "kerberos_delegation"}.get(kind, "ad_acl_abuse")
    desc = (f"BloodHound/AD attack-path edge: principal '{edge['principal']}' holds "
            f"'{edge['right']}' over '{edge['target']}'.")
    if edge.get("why"):
        desc += f" ({edge['why']})"
    impact = {
        "adcs_esc": "Enroll a certificate impersonating a privileged principal (Administrator, -500 SID) "
                    "and authenticate as them via PKINIT — full domain compromise.",
        "dcsync": "Replicate the directory to dump every account's NT hash (incl. krbtgt) — "
                  "domain-wide credential compromise and golden-ticket capability.",
        "trust": "Cross-forest/domain lateral movement: a Kerberos ticket from one side is honoured by "
                 "the other; with SID filtering off, inject an extra-SID for privileged access across the trust.",
        "delegation": "Unconstrained delegation lets a coerced privileged account's (e.g. a DC's) TGT be "
                      "captured and replayed — a direct path to DCSync and full domain compromise. "
                      "Constrained/RBCD enables impersonation to the delegated service.",
    }.get(kind, f"Take over '{edge['target']}' via the ACL edge, advancing toward domain compromise.")
    return {
        "id": "",  # filled by caller (bh-NNNN)
        "title": edge_title(edge),
        "severity": edge["severity"].upper(),
        "vuln_type": vuln_type,
        "endpoint": str(edge["target"]),  # non-http -> Ghostwriter network finding type
        "description": desc,
        "impact": impact,
        "remediation": ("Remove the dangerous ACE / restrict template enrollment and set manager-approval; "
                        "tier privileged accounts; monitor for the abuse primitive. "
                        f"Abuse primitive: {edge['abuse']}"),
        "reproduction_steps": [edge["abuse"]],
        "poc_request": edge["abuse"],
        "cwe": "CWE-266" if kind != "adcs_esc" else "CWE-295",
        "status": "confirmed",
        "evidence": {"oplog_id": oplog_id} if oplog_id else {},
    }
