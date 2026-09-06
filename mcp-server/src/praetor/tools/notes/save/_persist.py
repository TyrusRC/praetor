"""Persistence side of save_finding: the likely_false_positive shortcut, the
Burp submit + local write path, and the Rule 18 auto-annotate/Organizer hook."""

from datetime import datetime, timezone

from praetor import client
from praetor.tools.report.severity import sort_findings_by_risk

from .._helpers import (
    _dedupe_finding,
    _findings_lock,
    _hard_delete_finding,
    _load_findings_file,
    _safe_findings_path,
    _sanitized,
    _write_findings_file,
)


async def handle_false_positive(
    resolved_domain: str,
    endpoint: str,
    vuln_type: str,
    title: str,
    parameter: str,
) -> str:
    """Status='likely_false_positive' shortcut: hard-delete a matching prior
    record. likely_false_positive is never persisted as a finding."""
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


async def submit_and_persist(
    *,
    title: str,
    description: str,
    severity: str,
    endpoint: str,
    evidence_text: str,
    evidence: dict,
    vuln_type: str,
    status: str,
    reproductions,
    chain_with,
    human_verified: bool,
    overrides,
    parameter: str,
    confidence: float,
    impact: str,
    remediation: str,
    poc_request: str,
    reproduction_steps,
    cwe: str,
    cvss4_vector: str,
    cvss4_severity: str,
    resolved_domain: str,
) -> str:
    """Zero-noise submit then local persist. Burp is called first: if the
    server rejects (missing evidence index, NEVER SUBMIT without chain, missing
    reproductions), nothing is persisted to .burp-intel/findings.json — else
    rejected findings accumulate locally and re-load next session."""
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
            "reproductions_required": "Pass reproductions=[{logger_index,elapsed_ms,status_code}, ...] (>=3).",
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
    saved_entry = None
    if resolved_domain:
        findings_path = _safe_findings_path(resolved_domain)
        with _findings_lock(findings_path):
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
                "impact": impact,
                "remediation": remediation,
                "poc_request": poc_request,
                "reproduction_steps": reproduction_steps or [],
                "cwe": cwe,
                "cvss4_vector": cvss4_vector,
                "cvss4_severity": cvss4_severity,
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
            saved_entry = updated_list[idx]
            saved_id = saved_entry.get("id", "")
            # Highest severity first, so re-severity of an old finding moves it to
            # the top of the board instead of staying buried at its insertion
            # position. IDs are stable, so reordering is safe for chain_with[].
            store["findings"] = sort_findings_by_risk(updated_list)
            store["last_modified"] = now
            _write_findings_file(findings_path, store)
        # Projection: human-readable writeup from the canonical record (best-effort).
        from .._projection import write_finding_projection
        write_finding_projection(resolved_domain, saved_entry)

    if not resolved_domain:
        return (
            f"Finding saved to Burp in-memory only [{severity}] {title} (Burp ID: {burp_id}).\n"
            "Warning: no domain passed and could not derive from endpoint. "
            "Finding will be lost on Burp reload. Pass `domain=...` to persist."
        )

    organizer_note = await _auto_annotate_organizer(
        status, evidence, severity, saved_id, vuln_type, title, endpoint
    )

    action_label = "Updated" if dedup_action == "updated" else "Saved"
    return (
        f"{action_label} [{severity}] c={confidence:.2f} {title}\n"
        f"  Persistent ID: {saved_id} ({resolved_domain})\n"
        f"  Burp ID: {burp_id}\n"
        f"  Location: .burp-intel/{_sanitized(resolved_domain)}/findings.json"
        f"{organizer_note}"
    )


async def _auto_annotate_organizer(
    status: str,
    evidence,
    severity: str,
    saved_id: str,
    vuln_type: str,
    title: str,
    endpoint: str,
) -> str:
    # ── Rule 18 (BSCP operator workflow): auto-annotate the confirming
    # request and send it to Burp's Organizer the instant a finding is
    # confirmed — exactly what a practitioner does by hand. The colour
    # encodes severity (RED=crit/high, ORANGE=medium, YELLOW=low) and the
    # comment carries the finding id so the annotation is a resolvable
    # claim. Best-effort: the finding is already persisted above, so a Burp
    # hiccup here must never fail the save.
    organizer_note = ""
    if status == "confirmed" and isinstance(evidence, dict):
        ev_idx = evidence.get("logger_index")
        if ev_idx is None:
            ev_idx = evidence.get("proxy_history_index")
        if isinstance(ev_idx, int) and ev_idx >= 0:
            color = {
                "CRITICAL": "RED", "HIGH": "RED", "MEDIUM": "ORANGE",
                "LOW": "YELLOW",
            }.get(str(severity).upper(), "CYAN")
            comment = f"{saved_id} | {vuln_type or 'finding'} | {title}"[:200]
            try:
                ann = await client.post("/api/annotations/set", json={
                    "index": ev_idx, "color": color,
                    "comment": comment, "endpoint": endpoint,
                })
                if isinstance(ann, dict) and "error" not in ann:
                    await client.post(
                        "/api/organizer/send", json={"index": ev_idx})
                    organizer_note = (
                        f"\n  Burp: annotated #{ev_idx} {color} "
                        f"+ sent to Organizer ({comment})"
                    )
            except Exception:
                organizer_note = ""  # never block the save on Burp I/O
    return organizer_note
