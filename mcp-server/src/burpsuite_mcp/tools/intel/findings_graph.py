"""build_findings_graph — cross-engagement typed-edge graph over .burp-intel/.

Walks every `.burp-intel/<domain>/findings.json` and emits a graph of typed
edges so chain candidates surface across the entire engagement (not just per-
target).

Edge types:
  - shares_tech       : two findings on different domains with matching tech_stack overlap
  - shares_vuln_class : two findings with the same vuln_type
  - victim_to_attacker: finding A's evidence (e.g. leaked credential) is referenced in finding B's body
  - chain             : explicit chain link saved by `save_finding(chain_with=[...])`
  - same_endpoint     : two findings on identical (domain, endpoint, parameter)

Output is markdown for human review plus a JSON file written under
`.burp-intel/_graph/graph.json` for programmatic re-read.
"""

import asyncio
import json
from collections import defaultdict
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._internals import _atomic_write_json, _intel_root


def register(mcp: FastMCP):

    @mcp.tool()
    async def build_findings_graph(
        min_severity: str = "low",
        limit_per_edge_type: int = 50,
    ) -> str:
        """Build a typed-edge graph over all saved findings across every target.

        Args:
            min_severity: Drop findings below this severity (low / medium / high / critical).
            limit_per_edge_type: Cap edges per type in the textual report (graph.json has them all).
        """
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3, "info": -1, "informational": -1}
        sev_floor = sev_order.get(min_severity.lower(), 0)
        intel_root = _intel_root()
        if not intel_root.exists():
            return "No .burp-intel/ directory yet — nothing to graph."

        def _scan() -> list[dict]:
            all_findings = []
            for domain_dir in intel_root.iterdir():
                if not domain_dir.is_dir() or domain_dir.name.startswith("_"):
                    continue
                fp = domain_dir / "findings.json"
                profile_path = domain_dir / "profile.json"
                profile: dict = {}
                if profile_path.exists():
                    try:
                        profile = json.loads(profile_path.read_text())
                    except Exception:
                        profile = {}
                if not fp.exists():
                    continue
                try:
                    data = json.loads(fp.read_text())
                except Exception:
                    continue
                for f in data.get("findings", []):
                    if sev_order.get((f.get("severity") or "").lower(), 0) < sev_floor:
                        continue
                    f2 = dict(f)
                    f2["_domain"] = domain_dir.name
                    f2["_tech"] = profile.get("tech_stack", []) + profile.get("frameworks", [])
                    all_findings.append(f2)
            return all_findings

        findings = await asyncio.to_thread(_scan)
        if not findings:
            return "No findings at or above min_severity."

        # Build edges
        edges = defaultdict(list)
        for i, a in enumerate(findings):
            for j, b in enumerate(findings):
                if i >= j:
                    continue
                a_id = f"{a['_domain']}#{a.get('id', a.get('title', i))}"
                b_id = f"{b['_domain']}#{b.get('id', b.get('title', j))}"
                # shares_tech (cross-domain only)
                if a["_domain"] != b["_domain"]:
                    overlap = {t.lower() for t in a["_tech"]} & {t.lower() for t in b["_tech"]}
                    if overlap:
                        edges["shares_tech"].append({"src": a_id, "dst": b_id, "via": sorted(overlap)})
                # shares_vuln_class
                if a.get("vuln_type") and a.get("vuln_type") == b.get("vuln_type"):
                    edges["shares_vuln_class"].append({"src": a_id, "dst": b_id, "via": a["vuln_type"]})
                # same_endpoint
                if (a.get("endpoint") and a.get("endpoint") == b.get("endpoint")
                        and a.get("parameter", "") == b.get("parameter", "")):
                    edges["same_endpoint"].append({"src": a_id, "dst": b_id, "via": a["endpoint"]})

            # Explicit chain edges saved on the finding itself
            for chain_id in (a.get("chain_with") or []):
                a_id = f"{a['_domain']}#{a.get('id', a.get('title', i))}"
                edges["chain"].append({"src": a_id, "dst": chain_id})

            # victim_to_attacker: look for leaked credential / token references in description/evidence
            body_text = json.dumps(a.get("evidence", {})) + (a.get("description", "") or "")
            for j, b in enumerate(findings):
                if i == j:
                    continue
                b_evidence = json.dumps(b.get("evidence", {})) + (b.get("description", "") or "")
                # Look for any non-trivial token (>=10 chars) shared between bodies
                a_tokens = {t for t in body_text.split() if len(t) >= 10 and not t.isalpha()}
                if a_tokens & {t for t in b_evidence.split() if len(t) >= 10}:
                    a_id = f"{a['_domain']}#{a.get('id', a.get('title', i))}"
                    b_id = f"{b['_domain']}#{b.get('id', b.get('title', j))}"
                    edges["victim_to_attacker"].append({"src": a_id, "dst": b_id})

        graph = {
            "node_count": len(findings),
            "nodes": [
                {
                    "id": f"{f['_domain']}#{f.get('id', f.get('title', i))}",
                    "domain": f["_domain"],
                    "vuln_type": f.get("vuln_type", "?"),
                    "severity": f.get("severity", "?"),
                    "title": f.get("title", ""),
                    "endpoint": f.get("endpoint", ""),
                    "status": f.get("status", "?"),
                }
                for i, f in enumerate(findings)
            ],
            "edges": dict(edges),
        }

        graph_dir = intel_root / "_graph"
        graph_dir.mkdir(parents=True, exist_ok=True)
        graph_path = graph_dir / "graph.json"
        await asyncio.to_thread(_atomic_write_json, graph_path, graph)

        lines = [
            f"build_findings_graph — {len(findings)} findings",
            f"Wrote: {graph_path}",
            "",
            f"--- Nodes by severity ---",
        ]
        sev_count: dict[str, int] = defaultdict(int)
        for f in findings:
            sev_count[(f.get("severity") or "?").lower()] += 1
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_count[sev]:
                lines.append(f"  {sev}: {sev_count[sev]}")
        lines.append("")

        for edge_type in ("chain", "victim_to_attacker", "same_endpoint", "shares_vuln_class", "shares_tech"):
            edge_list = edges.get(edge_type, [])
            if not edge_list:
                continue
            lines.append(f"--- {edge_type} ({len(edge_list)}) ---")
            for e in edge_list[:limit_per_edge_type]:
                via = e.get("via", "")
                via_str = f" via {via}" if via else ""
                lines.append(f"  {e['src']} -> {e['dst']}{via_str}")
            if len(edge_list) > limit_per_edge_type:
                lines.append(f"  ... +{len(edge_list)-limit_per_edge_type} more (see graph.json) ...")
            lines.append("")

        # Suggest chains
        chain_seeds = [e for e in edges.get("chain", [])] + [e for e in edges.get("victim_to_attacker", [])]
        if chain_seeds:
            lines.append("--- Suggested chains ---")
            for e in chain_seeds[:10]:
                lines.append(f"  Investigate: {e['src']} -> {e['dst']}")
        return "\n".join(lines)
