"""Write-side notes tools: save_finding, mark_finding_false_positive,
hydrate_burp_findings. Mutates findings.json and Burp in-memory store."""

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._helpers import (
    _compact_and_remap_findings,
    _dedupe_finding,
    _domain_from_endpoint,
    _find_by_id,
    _format_proof_for_review,
    _hard_delete_finding,
    _intel_dir,
    _load_findings_file,
    _safe_findings_path,
    _sanitized,
    _write_findings_file,
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def save_finding(
        title: str,
        description: str,
        evidence: dict,
        severity: str = "INFO",
        endpoint: str = "",
        evidence_text: str = "",
        reproductions: list[dict] | None = None,
        chain_with: list[str] | None = None,
        status: str = "suspected",
        domain: str = "",
        parameter: str = "",
        vuln_type: str = "",
        confidence: float = 0.5,
        force_recon_gate: bool = False,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Save a pentest finding. Requires prior assess_finding() call. Burp hard-rejects missing evidence.

        Args:
            title: Short finding title
            description: Detailed vulnerability description
            evidence: Dict with logger_index, proxy_history_index, or collaborator_interaction_id
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO. Operator-locked — wins over advisor's inferred severity. See user-override skill for routing guidance.
            endpoint: Affected URL/endpoint
            evidence_text: Freeform proof string for the report
            reproductions: Required for timing/blind vuln_types (>=2 dicts with logger_index/elapsed_ms/status_code)
            chain_with: Required for NEVER SUBMIT vuln_types — list of finding IDs for the chain
            status: suspected, confirmed, stale, or likely_false_positive
            domain: Target domain for persistent .burp-intel storage
            parameter: Parameter name (dedup key)
            vuln_type: Vulnerability class (e.g. sqli, xss, sqli_blind)
            confidence: 0.0-1.0 score
            force_recon_gate: Bypass the session-start recon gate (Rule 20a). Only use if recon is already in flight in this session and not yet persisted.
            human_verified: Operator confirmed visually in Burp UI / browser DevTools. Logged in finding metadata (R19).
            overrides: Audit-trailed gate bypasses (R20). Each entry "<gate>:<reason>". Stored in finding entry as 'overrides' for review.
        """
        # Severity is operator-locked. Validate but don't auto-adjust.
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        severity_upper = (severity or "INFO").upper()
        if severity_upper not in valid_severities:
            return (
                f"Error: invalid severity '{severity}'. Must be one of: "
                f"{', '.join(sorted(valid_severities))}. Operator owns severity choice; "
                f"see user-override skill for guidance."
            )
        severity = severity_upper

        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        # Tool-call format guard: if the caller's evidence_text contains
        # literal Anthropic-style tool-parameter markers, the harness almost
        # certainly truncated the parameter block — every later parameter
        # (status / vuln_type / parameter / confidence / chain_with) silently
        # reverted to defaults, producing a "saved but with empty fields"
        # finding that's hard to spot. Reject up-front with a precise hint.
        leak_markers = (
            "</evidence_text>",
            "</invoke>",
            "<status>",
            "<vuln_type>",
            "<parameter>",
            "<confidence>",
            "<chain_with>",
            "<human_verified>",
        )
        for m in leak_markers:
            if m in (evidence_text or ""):
                return (
                    f"Error: evidence_text contains tool-call leak marker {m!r}. "
                    "This usually means a malformed parameter block (the harness "
                    "swallowed later parameters into evidence_text, leaving "
                    "vuln_type / parameter / status / confidence at defaults). "
                    "Re-issue save_finding with a clean evidence_text and each "
                    "parameter as its own argument."
                )

        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # ── Status='likely_false_positive' shortcut ────────────────────
        if (status or "").lower() == "likely_false_positive":
            if not resolved_domain:
                return (
                    "Refusing to process likely_false_positive without a domain. "
                    "Pass domain= so we can locate any prior persisted record."
                )
            try:
                findings_path = _safe_findings_path(resolved_domain)
            except ValueError as e:
                return f"Error: {e}"
            existing = _load_findings_file(findings_path).get("findings", []) if findings_path.exists() else []
            new_key_ep = endpoint or ""
            new_key_vuln = (vuln_type or "").lower()
            new_key_title = (title or "").lower()
            new_key_param = parameter or ""
            target = None
            for f in existing:
                if (
                    f.get("endpoint", "") == new_key_ep
                    and (f.get("vuln_type", "") or "").lower() == new_key_vuln
                    and f.get("title", "").lower() == new_key_title
                    and f.get("parameter", "") == new_key_param
                ):
                    target = f
                    break
            if target is None:
                return (
                    "No prior finding matched on (endpoint, vuln_type, title, parameter). "
                    "Nothing persisted, nothing to delete. (likely_false_positive is "
                    "never saved — use mark_finding_false_positive(finding_id) for "
                    "explicit deletion of a known ID.)"
                )
            conf = float(target.get("confidence", 0.5) or 0.5)
            if conf >= 0.6:
                return (
                    f"Refusing to silent-delete via save_finding(status='likely_false_positive') — "
                    f"existing record has confidence={conf:.2f} (>=0.6 requires explicit review).\n"
                    f"Use: mark_finding_false_positive(finding_id='{target.get('id', '')}', "
                    f"domain='{resolved_domain}', confirmed_by_user=True, reason='<why>')"
                )
            deleted_locally, burp_msg = await _hard_delete_finding(resolved_domain, target)
            return (
                f"Hard-deleted FP {target.get('id', '?')} (confidence={conf:.2f}) "
                f"from {resolved_domain}.\n"
                f"  Local store: {'removed' if deleted_locally else 'no-op'}\n"
                f"  {burp_msg}"
            )

        # ── Rule 20a: recon gate ──────────────────────────────────
        override_set = {(o.split(":", 1)[0] if ":" in o else o).strip().lower()
                        for o in (overrides or [])}
        skip_recon_gate = force_recon_gate or "recon_gate" in override_set
        if resolved_domain and not skip_recon_gate:
            from burpsuite_mcp.tools.intel import recon_gate_check
            gate_err = recon_gate_check(resolved_domain)
            if gate_err is not None:
                return f"RECON GATE: {gate_err}"

        # ── R25: chain_with validator ─────────────────────────────
        if chain_with and resolved_domain:
            try:
                findings_path = _safe_findings_path(resolved_domain)
                if findings_path.exists():
                    existing = _load_findings_file(findings_path).get("findings", [])
                    by_id = {f.get("id", ""): f for f in existing if f.get("id")}
                    bad_chain: list[str] = []
                    for cid in chain_with:
                        anchor = by_id.get(cid)
                        if anchor is None:
                            bad_chain.append(f"{cid} (not found)")
                            continue
                        anchor_status = anchor.get("status", "")
                        if anchor_status in ("likely_false_positive", "stale"):
                            bad_chain.append(f"{cid} ({anchor_status})")
                    if bad_chain:
                        return (
                            f"CHAIN GATE: chain_with references dead anchors: "
                            f"{', '.join(bad_chain)}. Re-verify each before chaining, "
                            f"or pass overrides=['q4_dedup:reviewed'] only after manual confirmation."
                        )
            except (OSError, ValueError):
                pass  # best-effort

        # ZERO-NOISE GATE — call Burp first. If the server rejects (missing
        # evidence index, NEVER SUBMIT without chain, missing reproductions),
        # we MUST NOT persist anything to .burp-intel/findings.json. Otherwise
        # rejected findings accumulate locally and get re-loaded next session,
        # wasting tokens on phantom "confirmed" findings.
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "evidence_text": evidence_text,
            "evidence": evidence,
            "vuln_type": vuln_type,
            "status": status,
        }
        if reproductions:
            payload["reproductions"] = reproductions
        if chain_with:
            payload["chain_with"] = chain_with

        data = await client.post("/api/notes/findings", json=payload)
        if "error" in data:
            err_code = data.get("code", "")
            err_hint = data.get("hint", "")
            err_msg = data.get("error", "(no message)")
            retry_advice = {
                "never_submit": "Either pass chain_with=[<id>] OR set_program_policy() to remove the class.",
                "chain_unknown_id": "Run get_findings() to list valid chain anchor IDs.",
                "evidence_missing": "Pass evidence={'logger_index': <N>}.",
                "reproductions_required": "Pass reproductions=[{logger_index,elapsed_ms,status_code}, ...] (>=2).",
                "reproductions_invalid": "Each reproductions[] entry needs an integer logger_index in range.",
            }.get(err_code, "")
            parts = [f"Error (gate rejected — nothing persisted): {err_msg}"]
            if err_code:
                parts.append(f"  Error type: {err_code}")
            if err_hint:
                parts.append(f"  Hint: {err_hint}")
            if retry_advice:
                parts.append(f"  Retry: {retry_advice}")
            return "\n".join(parts)
        burp_id = data.get("id", "?")

        # Gate passed — now safe to persist locally.
        dedup_action = "created"
        saved_id = ""
        if resolved_domain:
            findings_path = _safe_findings_path(resolved_domain)
            store = _load_findings_file(findings_path)
            now = datetime.now(timezone.utc).isoformat()
            new_entry = {
                "title": title,
                "description": description,
                "severity": severity,
                "endpoint": endpoint,
                "evidence_text": evidence_text,
                "evidence": evidence,
                "human_verified": human_verified,
                "overrides": list(overrides or []),
                "reproductions": reproductions or [],
                "chain_with": chain_with or [],
                "status": status,
                "parameter": parameter,
                "vuln_type": vuln_type,
                "confidence": round(confidence, 2),
                "last_updated": now,
                "burp_id": str(burp_id) if burp_id != "?" else "",
            }
            existing_list = store.get("findings", [])
            updated_list, dedup_action, idx = _dedupe_finding(existing_list, new_entry)
            if dedup_action == "created":
                # Assign IDs monotonically (max-existing + 1), NEVER refilling
                # gaps. Refilling a gap left by a deleted finding would silently
                # alias old chain_with[] references to the new finding. Hard
                # delete normally compacts IDs via _compact_and_remap_findings;
                # this max+1 rule is defense if a delete bypassed that path.
                max_num = 0
                for f in updated_list:
                    fid = f.get("id", "")
                    if len(fid) == 4 and fid.startswith("f") and fid[1:].isdigit():
                        max_num = max(max_num, int(fid[1:]))
                updated_list[idx]["id"] = f"f{max_num + 1:03d}"
                updated_list[idx]["created"] = now
            saved_id = updated_list[idx].get("id", "")
            store["findings"] = updated_list
            store["last_modified"] = now
            _write_findings_file(findings_path, store)

        if not resolved_domain:
            return (
                f"Finding saved to Burp in-memory only [{severity}] {title} (Burp ID: {burp_id}).\n"
                "Warning: no domain passed and could not derive from endpoint. "
                "Finding will be lost on Burp reload. Pass `domain=...` to persist."
            )

        action_label = "Updated" if dedup_action == "updated" else "Saved"
        return (
            f"{action_label} [{severity}] c={confidence:.2f} {title}\n"
            f"  Persistent ID: {saved_id} ({resolved_domain})\n"
            f"  Burp ID: {burp_id}\n"
            f"  Location: .burp-intel/{_sanitized(resolved_domain)}/findings.json"
        )

    @mcp.tool()
    async def hydrate_burp_findings(domain: str = "all", include_suspected: bool = False) -> str:
        """Re-populate Burp's in-memory Findings tab from persisted .burp-intel findings. Use after extension reload.

        Args:
            domain: Specific domain to hydrate, or 'all' for every .burp-intel domain
            include_suspected: If True, also restore suspected/stale findings (default: confirmed-only)
        """
        targets: list[Path] = []
        intel_root = _intel_dir()
        if domain == "all":
            if intel_root.exists():
                for d in sorted(intel_root.iterdir()):
                    if d.is_dir() and (d / "findings.json").exists():
                        targets.append(d / "findings.json")
        else:
            p = _safe_findings_path(domain)
            if p.exists():
                targets.append(p)

        if not targets:
            return f"No findings.json found for {domain!r} under .burp-intel/. Nothing to hydrate."

        allowed_statuses = {"confirmed"}
        if include_suspected:
            allowed_statuses |= {"suspected", "stale"}

        restored = 0
        skipped_status = 0
        skipped_gate = 0
        skipped_dup = 0
        gate_errors: list[str] = []

        for path in targets:
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            findings = data.get("findings", [])

            for f in findings:
                status = f.get("status", "suspected")
                if status not in allowed_statuses:
                    skipped_status += 1
                    continue

                payload = {
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "INFO"),
                    "endpoint": f.get("endpoint", ""),
                    "evidence_text": f.get("evidence_text", ""),
                    "evidence": f.get("evidence", {}),
                    "vuln_type": f.get("vuln_type", ""),
                    "status": status,
                }
                if f.get("reproductions"):
                    payload["reproductions"] = f["reproductions"]
                if f.get("chain_with"):
                    payload["chain_with"] = f["chain_with"]

                resp = await client.post("/api/notes/findings", json=payload)
                if "error" in resp:
                    err = resp["error"]
                    if "duplicate" in err.lower() or "already" in err.lower():
                        skipped_dup += 1
                    else:
                        skipped_gate += 1
                        if len(gate_errors) < 5:
                            fid = f.get("id", "?")
                            gate_errors.append(f"  {fid} ({f.get('title','')[:40]}): {err[:120]}")
                    continue
                restored += 1

        lines = [
            f"Hydrated Burp Findings tab from {len(targets)} domain(s).",
            f"  Restored:        {restored}",
            f"  Skipped (status not in {sorted(allowed_statuses)}): {skipped_status}",
            f"  Skipped (already in Burp memory):                   {skipped_dup}",
            f"  Skipped (gate rejection — evidence index stale):    {skipped_gate}",
        ]
        if gate_errors:
            lines.append("")
            lines.append("First gate rejections (evidence indices likely no longer resolve):")
            lines.extend(gate_errors)
            lines.append("")
            lines.append("Persistent .burp-intel store unchanged. Re-capture the underlying")
            lines.append("requests via search_history / browser_crawl to make these visible.")

        return "\n".join(lines)

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
            return (
                f"DRY-RUN: would prune {len(dropped)} of {len(all_findings)} "
                f"findings from {domain} (keep_statuses={sorted(keep_set)}).\n"
                + "\n".join(preview) + extra +
                f"\n\nRe-call with confirm=True to apply. Survivors will be "
                f"renumbered f001..f{len(keep):03d} and chain_with[] refs rewritten."
            )

        kept, id_map = _compact_and_remap_findings(keep)
        store["findings"] = kept
        store["last_modified"] = datetime.now(timezone.utc).isoformat()
        _write_findings_file(findings_path, store)

        remap_summary = ", ".join(
            f"{old}->{new}" for old, new in list(id_map.items())[:10] if old != new
        )
        if not remap_summary:
            remap_summary = "(no remap needed — IDs already contiguous)"
        return (
            f"Pruned {len(dropped)} of {len(all_findings)} findings from {domain}.\n"
            f"  Kept: {len(kept)} (statuses: {sorted(keep_set)})\n"
            f"  Remap (first 10): {remap_summary}\n"
            f"  Burp in-memory store NOT touched — run "
            f"hydrate_burp_findings(domain='{domain}') to sync."
        )
