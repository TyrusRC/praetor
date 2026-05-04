"""auto_probe — knowledge-driven vulnerability probing with server-side matchers."""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY
from ._helpers import _load_all_knowledge


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def auto_probe(  # cost: expensive
        session: str,
        targets: list[dict],
        categories: list[str] | None = None,
        max_probes_per_param: int = 20,
        domain: str = "",
        force_recon_gate: bool = False,
        skip_already_covered: bool = True,
    ) -> str:
        """Knowledge-driven vulnerability probing with server-side matchers.

        Cost class: EXPENSIVE — sends N probes per parameter × multiple categories.
        Run discover_attack_surface first to scope `targets` instead of probing
        everything. Honors Rule 20a recon gate when `domain` is supplied.

        Args:
            session: Session name
            targets: Parameters to test (from discover_attack_surface)
            categories: Filter probe categories (empty = all)
            max_probes_per_param: Max probes per parameter (default 20). Real
                JWT/GraphQL/proto-pollution bypasses sit at variant 6+. Lower
                only if you explicitly want a fast first pass.
            domain: Target domain (enables recon-gate + coverage skip)
            force_recon_gate: Bypass recon gate for in-flight recon
            skip_already_covered: Skip (endpoint, param, category) tuples whose knowledge_version in coverage.json matches current. Eliminates re-test cycle (R13). Default True. Set False after knowledge base updates.
        """
        # ── Pre-flight session-auth assertion ─────────────────────────
        try:
            sess_info = await client.get("/api/session/list")
            if "error" not in sess_info:
                resp_text = str(sess_info)
                if session in resp_text and "Auth: no" in resp_text and "Cookies: 0" in resp_text:
                    pass  # warning surfaced via lines below if probe finds nothing
        except Exception:
            pass

        # ── Rule 20a: recon gate ──
        if domain and not force_recon_gate:
            from burpsuite_mcp.tools.intel import recon_gate_check
            gate_err = recon_gate_check(domain)
            if gate_err is not None:
                try:
                    import json as _json_b
                    from burpsuite_mcp.tools.intel import _intel_path
                    profile_path = _intel_path(domain) / "profile.json"
                    profile_path.parent.mkdir(parents=True, exist_ok=True)
                    if not profile_path.exists():
                        profile_path.write_text(_json_b.dumps({
                            "domain": domain,
                            "auto_created": True,
                            "auto_created_by": "auto_probe",
                            "note": "Minimal stub. Run full_recon / discover_attack_surface to enrich.",
                        }, indent=2))
                except Exception:
                    pass

        # Load knowledge once; reused for coverage filter and the probe call.
        _knowledge = _load_all_knowledge(categories)

        # ── R13: filter targets against existing coverage ──
        skipped_count = 0
        if domain and skip_already_covered:
            try:
                from burpsuite_mcp.tools.intel import _knowledge_version, _intel_path
                cov_path = _intel_path(domain) / "coverage.json"
                if cov_path.exists():
                    cov = json.loads(cov_path.read_text())
                    cur_kv = _knowledge_version()
                    covered_keys: set[tuple] = set()
                    for entry in cov.get("entries", []):
                        if entry.get("knowledge_version") == cur_kv:
                            covered_keys.add((
                                entry.get("endpoint", ""),
                                entry.get("parameter", ""),
                                entry.get("category", ""),
                            ))
                    if covered_keys:
                        active_cats = set(categories or [
                            k.get("category") for k in _knowledge
                        ])
                        new_targets = []
                        for t in targets:
                            ep = t.get("path", "")
                            par = t.get("parameter", "")
                            cats_to_run = [c for c in active_cats if (ep, par, c) not in covered_keys]
                            if cats_to_run:
                                new_targets.append(t)
                            else:
                                skipped_count += 1
                        targets = new_targets
            except (OSError, json.JSONDecodeError, ValueError):
                pass

        knowledge = _knowledge
        if not knowledge:
            available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
            return f"No knowledge base found. Available: {', '.join(sorted(available))}"
        if not targets:
            return (
                f"All requested targets already covered (knowledge_version match). "
                f"Skipped {skipped_count} tuples. Pass skip_already_covered=False to re-probe."
            )

        data = await client.post("/api/session/auto-probe", json={
            "session": session,
            "targets": targets,
            "knowledge": knowledge,
            "max_probes_per_param": max_probes_per_param,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auto-Probe: {data.get('parameters_tested', 0)} params, {data.get('total_probes_sent', 0)} probes\n"]

        findings = data.get("findings", [])
        for f in findings:
            raw = f.get("confidence", f.get("score", 0) / 100.0)
            f["confidence"] = max(0.0, min(1.0, raw))
        findings_sorted = sorted(
            findings,
            key=lambda f: (f["confidence"], f.get("score", 0)),
            reverse=True,
        )

        # Auto-annotate proxy history (Rule 31). Run gather concurrently — sequential
        # awaits cost ~50ms each, compounded to 1-2s on 30-finding runs.
        async def _annotate(finding: dict) -> bool:
            idx = finding.get("history_index") or finding.get("proxy_index") or finding.get("logger_index")
            if idx is None:
                return False
            conf = finding.get("confidence", 0) or 0
            color = (
                "RED" if conf >= 0.90 else
                "ORANGE" if conf >= 0.60 else
                "YELLOW" if conf >= 0.30 else
                "GRAY"
            )
            cat = finding.get("category", "?")
            ctx = finding.get("context", "?")
            param = finding.get("parameter", "?")
            comment = f"auto_probe | {cat}/{ctx} | param={param} | c={conf:.2f}"
            try:
                await client.post("/api/annotations/set", json={
                    "index": int(idx),
                    "color": color,
                    "comment": comment[:300],
                })
                return True
            except Exception:
                return False

        ann_results = await asyncio.gather(*(_annotate(f) for f in findings_sorted), return_exceptions=True)
        annotated = sum(1 for r in ann_results if r is True)

        if findings_sorted:
            lines.append(f"Findings ({len(findings_sorted)}):\n")
            for finding in findings_sorted:
                sev = finding.get("severity", "?")
                score = finding.get("score", 0)
                conf = finding.get("confidence")
                anomaly = finding.get("anomaly_score", 0)
                color = (
                    "RED" if conf is not None and conf >= 0.90 else
                    "ORA" if conf is not None and conf >= 0.60 else
                    "YEL" if conf is not None and conf >= 0.30 else
                    "GRN"
                )
                conf_str = f"c={conf:.2f} [{color}]" if conf is not None else f"score={score}"
                lines.append(f"  [{sev:>8s}] {conf_str}  {finding.get('endpoint', '?')} -> {finding.get('parameter', '?')}")
                lines.append(f"           {finding.get('category', '?')}/{finding.get('context', '?')}: {finding.get('description', '?')}")
                lines.append(f"           Payload: {finding.get('probe', '?')}")
                matched = finding.get("matched_matchers", [])
                if matched:
                    lines.append(f"           Matchers: {', '.join(str(m) for m in matched)}")
                anomalies = finding.get("anomalies", [])
                if anomalies:
                    lines.append(f"           Anomalies: {', '.join(anomalies)} (anomaly_score: {anomaly})")
                lines.append("")
        else:
            lines.append("No vulnerabilities detected.")

        saved = data.get("auto_saved_findings", 0)
        if saved:
            lines.append(f"\n{saved} findings detected. Pass the confidence value to save_finding(confidence=...) or export_report() for report.")
        if annotated:
            lines.append(f"Auto-annotated {annotated} proxy-history entries with severity colours (Rule 31).")

        return "\n".join(lines)
