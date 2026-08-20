"""mark_finding_false_positive + prune_findings — deletion and compaction."""

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.report.severity import sort_findings_by_risk

from .._helpers import (
    _annotation_remap_impact,
    _compact_and_remap_findings,
    _find_by_id,
    _format_proof_for_review,
    _hard_delete_finding,
    _load_findings_file,
    _prospective_id_map,
    _safe_findings_path,
    _write_findings_file,
    resync_burp_annotations,
)


def register(mcp: FastMCP):
    @mcp.tool()
    async def mark_finding_false_positive(
        finding_id: str,
        domain: str,
        confirmed_by_user: bool = False,
        force: bool = False,
        reason: str = "",
    ) -> str:
        """Hard-delete a saved finding and its Burp in-memory mirror.

        Confidence-tiered review (operator-set policy):
          - confidence < 0.6           → delete immediately, no prompt.
          - 0.6 <= confidence < 0.8    → returns full evidence dump and asks the
                                         operator to re-call with confirmed_by_user=True.
          - confidence >= 0.8          → refuses unless force=True with reason — looks
                                         like a real finding; operator must override.

        Args:
            finding_id: Persistent ID, e.g. 'f003'
            domain:     Target domain (where the finding lives in .burp-intel)
            confirmed_by_user: Set True to confirm a 0.6–0.8 borderline deletion.
            force:      Set True to override the >=0.8 refusal. Requires reason.
            reason:     Audit trail — why is this an FP? Required for force=True.
        """
        if not domain:
            return "Error: domain is required to locate the finding."
        try:
            findings_path = _safe_findings_path(domain)
        except ValueError as e:
            return f"Error: {e}"
        if not findings_path.exists():
            return f"No findings.json for domain {domain!r}."
        store = _load_findings_file(findings_path)
        all_findings = store.get("findings", [])
        idx, target = _find_by_id(all_findings, finding_id)
        if target is None:
            return (
                f"Finding {finding_id!r} not found in {domain}. "
                f"Existing IDs: {', '.join(f.get('id', '?') for f in all_findings) or '(none)'}"
            )

        conf = float(target.get("confidence", 0.5) or 0.5)
        proof_block = _format_proof_for_review(target)

        # Tier 3: high-confidence — looks like a real finding.
        if conf >= 0.8:
            if not force:
                return (
                    f"REFUSING to delete {finding_id} — confidence={conf:.2f} "
                    f"(>=0.8 = looks like a real finding).\n"
                    f"\nFull record:\n{proof_block}\n"
                    f"\nIf you have manually verified this is an FP (target patched, "
                    f"original reproduction was a misread, etc.), re-call with:\n"
                    f"  mark_finding_false_positive(finding_id='{finding_id}', "
                    f"domain='{domain}', force=True, reason='<one-line why>')"
                )
            if not reason.strip():
                return (
                    f"REFUSING to force-delete {finding_id} without a reason. "
                    f"force=True requires reason='<why this confirmed/high-conf "
                    f"finding is actually FP>' for the audit trail."
                )

        # Tier 2: borderline — operator must say yes.
        elif 0.6 <= conf < 0.8:
            if not confirmed_by_user:
                return (
                    f"BORDERLINE FP — confidence={conf:.2f} on {finding_id}. "
                    f"Showing full evidence; operator decides.\n"
                    f"\n{proof_block}\n"
                    f"\nIf this is genuinely an FP, re-call with:\n"
                    f"  mark_finding_false_positive(finding_id='{finding_id}', "
                    f"domain='{domain}', confirmed_by_user=True, reason='<why>')\n"
                    f"\nIf the suspicion is still real but unverified, leave it alone "
                    f"or update via save_finding(status='suspected', ...)."
                )

        # Tier 1: low-conf or all gates passed → hard delete.
        deleted_locally, burp_msg = await _hard_delete_finding(domain, target)
        audit = []
        audit.append(f"Hard-deleted {finding_id} (confidence={conf:.2f}, "
                     f"severity={target.get('severity', 'INFO')}) from {domain}.")
        audit.append(f"  Local store: {'removed' if deleted_locally else 'no-op'}")
        audit.append(f"  {burp_msg}")
        if force:
            audit.append(f"  Force-delete reason: {reason}")
        elif confirmed_by_user:
            audit.append(f"  Operator-confirmed reason: {reason or '(none given)'}")
        return "\n".join(audit)

    @mcp.tool()
    async def prune_findings(
        domain: str,
        keep_statuses: list[str] | None = None,
        confirm: bool = False,
    ) -> str:
        """Drop non-value findings from .burp-intel/<domain>/findings.json and
        compact surviving IDs.

        Defaults to keeping only `confirmed` findings — same status set the
        reporting pipeline uses. Pass `keep_statuses` to widen (e.g.
        ['confirmed','suspected']).

        Survivors are renumbered contiguously (f001..f00N) and chain_with[]
        references are rewritten; refs pointing at pruned IDs are dropped.

        Burp's in-memory store is NOT touched — call hydrate_burp_findings()
        after pruning if you want the Burp Findings tab to match.

        Args:
            domain:        Target domain.
            keep_statuses: Status values to retain. Default ['confirmed'].
            confirm:       Must be True to actually mutate. Dry-run otherwise.
        """
        if not domain:
            return "Error: domain is required."
        keep_set = {s.lower().strip() for s in (keep_statuses or ["confirmed"])}
        try:
            findings_path = _safe_findings_path(domain)
        except ValueError as e:
            return f"Error: {e}"
        if not findings_path.exists():
            return f"No findings.json for {domain!r} — nothing to prune."
        store = _load_findings_file(findings_path)
        all_findings = store.get("findings", [])
        if not all_findings:
            return f"{domain}: findings.json empty — nothing to prune."

        keep = [f for f in all_findings if (f.get("status") or "").lower() in keep_set]
        dropped = [f for f in all_findings if (f.get("status") or "").lower() not in keep_set]

        if not dropped:
            return (
                f"{domain}: no findings to prune (all {len(all_findings)} match "
                f"keep_statuses={sorted(keep_set)})."
            )

        if not confirm:
            preview = [
                f"  {f.get('id', '?'):5} [{f.get('status', '?'):20}] "
                f"{f.get('severity', 'INFO'):8} {f.get('title', '')[:80]}"
                for f in dropped[:20]
            ]
            extra = "" if len(dropped) <= 20 else f"\n  ... and {len(dropped) - 20} more"
            # Question gate — Burp proxy-history impact. Renumbering survivors
            # changes the finding-id cited in the annotations that back the
            # report. Name exactly which history comments will be rewritten so
            # the operator confirms with the report consequence in view.
            impact = _annotation_remap_impact(keep, _prospective_id_map(keep))
            history_lines = ""
            if impact:
                touched_idx = sum(len(i["indices"]) for i in impact)
                rows = [
                    f"    {i['old']} -> {i['new']}  (proxy history {', '.join('#' + str(x) for x in i['indices'])})"
                    for i in impact[:10]
                ]
                more = "" if len(impact) <= 10 else f"\n    ... and {len(impact) - 10} more findings"
                history_lines = (
                    f"\n\nBURP HISTORY IMPACT — {touched_idx} annotated proxy "
                    f"entr{'y' if touched_idx == 1 else 'ies'} across {len(impact)} "
                    f"finding(s) back the report and cite an id that will change:\n"
                    + "\n".join(rows) + more +
                    "\n  On confirm these comments are rewritten in Burp to the new "
                    "ids (best-effort — reconnect Burp first so none go stale)."
                )
            return (
                f"DRY-RUN: would prune {len(dropped)} of {len(all_findings)} "
                f"findings from {domain} (keep_statuses={sorted(keep_set)}).\n"
                + "\n".join(preview) + extra +
                f"\n\nRe-call with confirm=True to apply. Survivors will be "
                f"renumbered f001..f{len(keep):03d} and chain_with[] refs rewritten."
                + history_lines
            )

        kept, id_map = _compact_and_remap_findings(keep)
        # Keep the report evidence consistent: rewrite the Burp proxy-history
        # comments that cite a renumbered id (mutates the annotation records
        # in-place, so the write below persists the corrected text).
        resync = await resync_burp_annotations(kept, id_map)
        store["findings"] = sort_findings_by_risk(kept)
        store["last_modified"] = datetime.now(timezone.utc).isoformat()
        _write_findings_file(findings_path, store)

        remap_summary = ", ".join(
            f"{old}->{new}" for old, new in list(id_map.items())[:10] if old != new
        )
        if not remap_summary:
            remap_summary = "(no remap needed — IDs already contiguous)"
        history_line = ""
        if resync["resynced"] or resync["unreachable"]:
            history_line = (
                f"\n  Burp history: {resync['resynced']} comment(s) rewritten to new ids"
                + (
                    f", {resync['unreachable']} unreachable (Burp down / history "
                    f"cleared — re-annotate after reconnect)"
                    if resync["unreachable"]
                    else ""
                )
            )
        return (
            f"Pruned {len(dropped)} of {len(all_findings)} findings from {domain}.\n"
            f"  Kept: {len(kept)} (statuses: {sorted(keep_set)})\n"
            f"  Remap (first 10): {remap_summary}"
            + history_line +
            f"\n  Burp in-memory store NOT touched — run "
            f"hydrate_burp_findings(domain='{domain}') to sync."
        )
