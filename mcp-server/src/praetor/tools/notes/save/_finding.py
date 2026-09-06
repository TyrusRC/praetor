"""save_finding — the gated write path for a pentest finding (Rule 10c)."""

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._vuln_class import canonical
from praetor.tools.advisor_kb import NEVER_SUBMIT_TYPES
from praetor.tools.report.severity import (
    SEVERITY_RANK,
    cvss4_for_finding,
    severity_cap_for,
    severity_cvss_conflict,
    sort_findings_by_risk,
    tier_guidance,
)

from .._helpers import (
    _dedupe_finding,
    _domain_from_endpoint,
    _findings_lock,
    _hard_delete_finding,
    _load_findings_file,
    _safe_findings_path,
    _sanitized,
    _write_findings_file,
)
from ._systemic import _find_systemic_sibling


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
        impact: str = "",
        remediation: str = "",
        poc_request: str = "",
        reproduction_steps: list[str] | None = None,
        cwe: str = "",
        cvss_vector: str = "",
        force_recon_gate: bool = False,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Save a pentest finding. Requires prior assess_finding(). Burp hard-rejects missing evidence.

        The report renders only what is stored here. A field left empty is a
        section the deliverable omits — it is never filled in later from
        recollection, which is how reports end up describing a PoC nobody ran.

        Args:
            title: Short finding title.
            description: Detailed vulnerability description.
            evidence: Dict with logger_index, proxy_history_index, or collaborator_interaction_id.
            severity: CRITICAL/HIGH/MEDIUM/LOW/INFO. Operator-locked — wins over advisor's inferred severity.
            endpoint: Affected URL/endpoint.
            evidence_text: Freeform proof string for the report.
            reproductions: Required for timing/blind vuln_types (>=3 dicts with logger_index/elapsed_ms/status_code, per Rule 10a).
            chain_with: Required for NEVER-SUBMIT vuln_types — list of finding IDs for the chain.
            status: suspected/confirmed/stale/likely_false_positive.
            domain: Target domain for persistent .burp-intel storage.
            parameter: Parameter name (dedup key).
            vuln_type: Vuln class (e.g. sqli, xss, sqli_blind).
            confidence: 0.0-1.0 score.
            impact: What an attacker GAINS — whose data, which action, what they
                obtain that they could not get legitimately. Required for
                MEDIUM and above: a finding that cannot state this is what
                programs close as Informative.
            remediation: The fix, specific to this endpoint/parameter.
            poc_request: Raw HTTP request that demonstrates the issue.
            reproduction_steps: Cold-start steps a triager can follow.
            cwe: CWE id (e.g. 'CWE-89'). Blank falls back to the class map.
            cvss_vector: Explicit CVSS 4.0 vector. Blank derives one from
                vuln_type + evidence shape flags; the derived band is
                cross-checked against `severity`.
            force_recon_gate: Bypass session-start recon gate (Rule 20a); only if recon is in flight and not yet persisted.
            human_verified: Operator confirmed visually in Burp/DevTools. Logged in metadata.
            overrides: Audit-trailed gate bypasses (R20), each "<gate>:<reason>".
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

        override_set = {(o.split(":", 1)[0] if ":" in o else o).strip().lower()
                        for o in (overrides or [])}

        # ── NEVER-SUBMIT gate (canonicalized) ─────────────────────
        # The authoritative Java gate matches vuln_type raw against a
        # differently-spelled set (open_redirect_no_chain, missing_security_header,
        # ...), so a finding tagged in its canonical Python spelling
        # (open_redirect, missing_headers, cookie_flags) slips past the very
        # hard-reject _vuln_class.canonical() exists to enforce — the same
        # spelling bypass q6_never_submit already fixed on the advisory path.
        # Close it here, in the layer that owns canonicalization: an
        # unconditional NEVER-SUBMIT class is reportable only chained.
        canon_vuln = canonical(vuln_type)
        if (
            canon_vuln in NEVER_SUBMIT_TYPES
            and not chain_with
            and "q6_never_submit" not in override_set
            and "never_submit" not in override_set
        ):
            return (
                f"NEVER-SUBMIT GATE: '{vuln_type}' ({canon_vuln}) — "
                f"{NEVER_SUBMIT_TYPES[canon_vuln]}.\n"
                "  Standalone it is noise a triager closes Informative. Report it\n"
                "  only chained into real impact: pass chain_with=['fNNN'].\n"
                "  Deliberate exception: overrides=['q6_never_submit:<reason>']."
            )

        # ── INFO gate: a finding board starts at LOW ──
        # An INFO observation is an input to the next question, not an output to
        # file. Saving it makes it a "finding": it lands on the board, reloads
        # every session, gets counted in the report, and ends up submitted and
        # closed Informative. Leads belong in notes.md, where they cost nothing
        # and stay available for the escalation that turns them into a finding.
        if severity == "INFO" and "severity_info" not in override_set:
            return (
                "INFO GATE: findings start at LOW. INFO is a lead, not a result.\n"
                f"  '{title}' describes something observed, not something an "
                f"attacker gains.\n"
                "  Ask what it ENABLES, then file the thing it enabled:\n"
                "    - leaked path / DB error / stack trace -> read the file, reach "
                "the host, or land the injection it points at;\n"
                "    - disclosed version -> land a working exploit for that version;\n"
                "    - enumeration oracle -> pair it with a working account attack.\n"
                "  If the escalation fails, record it with save_target_notes(domain, ...) "
                "so the next session has the lead without carrying a finding.\n"
                "  If it genuinely belongs in the deliverable as context, chain it: "
                "chain_with=['fNNN'].\n"
                "  Deliberate exception: overrides=['severity_info:<reason>']."
            )

        # ── Impact gate: MEDIUM+ must say what the attacker GAINS ──
        # Q3 in assess_finding demands this before the finding is approved; the
        # answer was then discarded and the report rendered no Impact section at
        # all, leaving it to be reconstructed from memory at write-up time.
        # Capturing it here is what makes the report evidence-backed.
        if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["MEDIUM"] and not impact.strip():
            if "q3_impact" not in override_set:
                return (
                    f"IMPACT GATE: severity={severity} requires impact='...'.\n"
                    f"  State what an attacker DOES with this — whose data, which "
                    f"action, what they gain that they could not get legitimately.\n"
                    f"  The report renders this verbatim; leaving it empty means the "
                    f"deliverable has no impact section and the claim gets closed "
                    f"Informative.\n"
                    f"  If the impact genuinely comes from a chain, pass "
                    f"chain_with=['fNNN'] and restate it here in one line.\n"
                    f"  Deliberate exception: overrides=['q3_impact:<reason>']."
                )

        # ── Severity vs CVSS 4.0 band ─────────────────────────────
        cvss4_vector, cvss4_severity = cvss4_for_finding(
            vuln_type, evidence=evidence if isinstance(evidence, dict) else {},
            explicit_vector=cvss_vector,
        )
        conflict = severity_cvss_conflict(
            severity, cvss4_severity, cap=severity_cap_for(vuln_type, title)
        )
        if conflict and "severity_cvss" not in override_set:
            return (
                f"SEVERITY/CVSS GATE: {conflict}.\n"
                f"  Vector: {cvss4_vector}\n"
                f"  A HIGH label on a LOW vector is the inflation triagers "
                f"downgrade on sight; a LOW label on a CRITICAL vector buries "
                f"the finding at the bottom of the report.\n"
                f"  Fix one of the two: set severity='{cvss4_severity}', or pass "
                f"cvss_vector='CVSS:4.0/...' reflecting the metrics you actually "
                f"observed (AV/AC/PR/UI and the VC/VI/VA impacts).\n"
                f"  Tiers, rated on business impact and not on how the bug was found:\n"
                f"{tier_guidance()}\n"
                f"  Deliberate exception: overrides=['severity_cvss:<reason>']."
            )

        # ── Systemic-duplicate gate ───────────────────────────────
        # The same root cause on a second endpoint is one systemic finding with
        # two affected locations, not two findings. Platforms pay the first
        # distinct report and discount or zero the rest, so splitting one
        # unparameterised-query bug across every page that reaches it converts
        # a full-value report into a pile of duplicates — and inflates the
        # board the operator has to read.
        if resolved_domain and status != "likely_false_positive" \
                and "systemic_dup" not in override_set:
            sibling = _find_systemic_sibling(
                resolved_domain, vuln_type, endpoint, parameter, title
            )
            if sibling is not None:
                others = sibling.get("_endpoints", [])
                return (
                    f"SYSTEMIC GATE: {sibling.get('id')} already reports "
                    f"{vuln_type or 'this class'} on this target.\n"
                    f"  Already covered: {', '.join(others[:5])}"
                    f"{' ...' if len(others) > 5 else ''}\n"
                    f"  New location:    {endpoint} ({parameter or 'no parameter'})\n"
                    "  Same root cause on another endpoint is one systemic finding with\n"
                    "  several affected locations — a second report is a duplicate and\n"
                    "  earns nothing. Add this endpoint to the existing finding's\n"
                    "  description and reproduction_steps instead.\n"
                    "  File separately only if the root cause is genuinely different\n"
                    "  (different code path, different sink, different fix): "
                    "overrides=['systemic_dup:<why this is a distinct defect>']."
                )

        # ── Rule 20a: recon gate ──────────────────────────────────
        skip_recon_gate = force_recon_gate or "recon_gate" in override_set
        if resolved_domain and not skip_recon_gate:
            from praetor.tools.intel import recon_gate_check
            gate_err = recon_gate_check(resolved_domain)
            if gate_err is not None:
                return gate_err  # already prefixed "RECON GATE:" by the checker

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

        action_label = "Updated" if dedup_action == "updated" else "Saved"
        return (
            f"{action_label} [{severity}] c={confidence:.2f} {title}\n"
            f"  Persistent ID: {saved_id} ({resolved_domain})\n"
            f"  Burp ID: {burp_id}\n"
            f"  Location: .burp-intel/{_sanitized(resolved_domain)}/findings.json"
            f"{organizer_note}"
        )
