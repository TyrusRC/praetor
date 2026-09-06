"""auto_probe — knowledge-driven vulnerability probing with server-side matchers."""

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY
from ._helpers import _load_all_knowledge
from ._prioritise import prioritise, target_tech_stack
# Re-exported so `praetor.tools.scan.auto_probe._rank_order_targets` stays a
# valid import target (the test suite imports it from here).
from ._impl import (  # noqa: F401
    _rank_order_targets,
    annotate_findings,
    filter_covered_targets,
    record_coverage,
)


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
        # ── Runtime guards: cost cap (hard stop) + loop detection ──
        from praetor.tools._runtime_guard import note_call
        from praetor.tools.intel.cost_cap import budget_gate
        _over = budget_gate(domain)
        if _over:
            return _over
        _cats = ",".join(sorted(categories)) if categories else "all"
        _tsig = "|".join(sorted(str(t.get("endpoint", t)) for t in targets))[:200]
        _loop = note_call("auto_probe", f"{session}:{_cats}:{hash(_tsig)}")
        if _loop:
            return _loop

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
            from praetor.tools.intel import recon_gate_check
            gate_err = recon_gate_check(domain)
            if gate_err is not None:
                try:
                    import json as _json_b
                    from praetor.tools.intel import _intel_path
                    profile_path = _intel_path(domain) / "profile.json"
                    profile_path.parent.mkdir(parents=True, exist_ok=True)
                    if not profile_path.exists():
                        profile_path.write_text(_json_b.dumps({
                            "domain": domain,
                            "auto_created": True,
                            "auto_created_by": "auto_probe",
                            "note": "Minimal stub. Run full_recon / discover_attack_surface to enrich.",
                        }, indent=2), encoding="utf-8")
                except Exception:
                    pass

        # Load knowledge once; reused for coverage filter and the probe call.
        _knowledge = _load_all_knowledge(categories)

        # ── R13: filter targets against existing coverage ──
        targets, skipped_count, kb_drift_hint = filter_covered_targets(
            domain, skip_already_covered, targets, categories, _knowledge
        )

        knowledge = _knowledge
        if not knowledge:
            available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
            return f"No knowledge base found. Available: {', '.join(sorted(available))}"
        if not targets:
            msg = (
                f"All requested targets already covered (knowledge_version match). "
                f"Skipped {skipped_count} tuples. Pass skip_already_covered=False to re-probe."
            )
            if kb_drift_hint:
                msg += "\n" + kb_drift_hint
            return msg

        # ── W36-P5: audit highest-value surface first ──
        # Order surviving targets by the rank_attack_targets risk engine so the
        # extension's per-target iteration probes the most valuable tuples early.
        targets = _rank_order_targets(targets)

        # Order the KNOWLEDGE the same way. The orchestrator walks this list and
        # stops at max_probes_per_param, so whatever leads the list is what gets
        # tested — and the list order was previously arbitrary. Unconstrained
        # contexts match every parameter and were spending the whole budget
        # before any parameter-specific class was reached.
        knowledge = prioritise(knowledge, targets, target_tech_stack(domain))

        data = await client.post("/api/session/auto-probe", json={
            "session": session,
            "targets": targets,
            "knowledge": knowledge,
            "max_probes_per_param": max_probes_per_param,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auto-Probe: {data.get('parameters_tested', 0)} params, {data.get('total_probes_sent', 0)} probes\n"]
        if kb_drift_hint:
            lines.append(kb_drift_hint)

        findings = data.get("findings", [])
        for f in findings:
            raw = f.get("confidence", f.get("score", 0) / 100.0)
            f["confidence"] = max(0.0, min(1.0, raw))
        findings_sorted = sorted(
            findings,
            key=lambda f: (f["confidence"], f.get("score", 0)),
            reverse=True,
        )

        annotated = await annotate_findings(findings_sorted)

        record_coverage(domain, data)

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

        # ── Partial-signal escalation hints ──
        # When a probe records anomalies (status/length/timing/header deltas)
        # but no matcher fired (or confidence < 0.30), the canonical payload
        # likely got filtered. Surface a copy-pasteable fuzz_with_feedback
        # invocation so the operator can mutate the payload and try again.
        partial = []
        for f in findings_sorted:
            conf = f.get("confidence", 0) or 0
            anomalies = f.get("anomalies", []) or []
            matched = f.get("matched_matchers", []) or []
            if anomalies and conf < 0.30 and not matched:
                partial.append(f)
        if partial:
            lines.append(f"\nPartial-signal escalation candidates ({len(partial)}):")
            lines.append("Anomaly seen but no matcher fired — payload likely filtered. Try mutation.")
            for f in partial[:5]:
                ep = f.get("endpoint", "?")
                param = f.get("parameter", "?")
                cat = f.get("category", "?")
                probe = f.get("probe", "")
                ans = f.get("anomalies", [])
                lines.append(
                    f"  • {cat}: {ep} param={param} anomalies={','.join(ans[:3])}"
                )
                if probe:
                    lines.append(
                        f"    → fuzz_with_feedback(url='{ep}', parameter='{param}', "
                        f"seed={probe!r}, signals={{'length_delta_min': 100, 'status_changed': True}})"
                    )

        return "\n".join(lines)
