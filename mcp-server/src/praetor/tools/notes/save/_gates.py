"""Pre-persist validation gates for save_finding (Rule 10c).

Each gate returns an error string that aborts the save, or None to proceed. All
are pure and synchronous except recon_gate, which resolves recon_gate_check via
an inline import at call time so the test patch target stays valid.
"""

from praetor.tools._vuln_class import canonical
from praetor.tools.advisor_kb import NEVER_SUBMIT_TYPES
from praetor.tools.report.severity import (
    SEVERITY_RANK,
    severity_cap_for,
    severity_cvss_conflict,
    tier_guidance,
)

from .._helpers import _load_findings_file, _safe_findings_path
from ._systemic import _find_systemic_sibling

# Tool-call format guard markers: if the caller's evidence_text contains any
# literal Anthropic-style tool-parameter marker, the harness almost certainly
# truncated the parameter block — every later parameter (status / vuln_type /
# parameter / confidence / chain_with) silently reverted to defaults, producing
# a "saved but with empty fields" finding that's hard to spot.
LEAK_MARKERS = (
    "</evidence_text>",
    "</invoke>",
    "<status>",
    "<vuln_type>",
    "<parameter>",
    "<confidence>",
    "<chain_with>",
    "<human_verified>",
)


def evidence_leak_gate(evidence_text: str) -> str | None:
    for m in LEAK_MARKERS:
        if m in (evidence_text or ""):
            return (
                f"Error: evidence_text contains tool-call leak marker {m!r}. "
                "This usually means a malformed parameter block (the harness "
                "swallowed later parameters into evidence_text, leaving "
                "vuln_type / parameter / status / confidence at defaults). "
                "Re-issue save_finding with a clean evidence_text and each "
                "parameter as its own argument."
            )
    return None


def never_submit_gate(vuln_type: str, chain_with, override_set: set) -> str | None:
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
    return None


def info_gate(severity: str, title: str, override_set: set) -> str | None:
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
    return None


def impact_gate(severity: str, impact: str, override_set: set) -> str | None:
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
    return None


def severity_cvss_gate(
    severity: str,
    cvss4_vector: str,
    cvss4_severity: str,
    vuln_type: str,
    title: str,
    override_set: set,
) -> str | None:
    # ── Severity vs CVSS 4.0 band ─────────────────────────────
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
    return None


def systemic_gate(
    resolved_domain: str,
    status: str,
    vuln_type: str,
    endpoint: str,
    parameter: str,
    title: str,
    override_set: set,
) -> str | None:
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
    return None


def recon_gate(resolved_domain: str, force_recon_gate: bool, override_set: set) -> str | None:
    # ── Rule 20a: recon gate ──────────────────────────────────
    skip_recon_gate = force_recon_gate or "recon_gate" in override_set
    if resolved_domain and not skip_recon_gate:
        from praetor.tools.intel import recon_gate_check
        gate_err = recon_gate_check(resolved_domain)
        if gate_err is not None:
            return gate_err  # already prefixed "RECON GATE:" by the checker
    return None


def chain_with_gate(chain_with, resolved_domain: str) -> str | None:
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
    return None
