"""CVSS scoring + severity reconciliation + debate-triage impls for the advisor.

Extracted from advisor/__init__ so the tool wrappers stay thin.
"""

from __future__ import annotations

from praetor.tools.advisor import _cvss4


async def compute_cvss_impl(
    vuln_type: str,
    requires_auth: bool = False,
    requires_admin: bool = False,
    requires_interaction: bool = False,
    oob_only: bool = False,
    subsequent_impact: str = "",
    exploit_maturity: str = "X",
    env_overrides: dict | None = None,
) -> dict:
    """Build CVSS 4.0 + CVSS 3.1 vectors for a finding, with categorical severity band.

    Returns {cvss4_vector, cvss4_macrovector, cvss4_band, cvss31_vector,
    suggested_overrides, note}. Operator-owned: caller passes finding shape
    flags (requires_auth, requires_interaction, subsequent_impact) and any
    Threat/Environmental metric overrides via env_overrides (e.g. {"E":"A","CR":"H"}).

    Args:
        vuln_type: Vulnerability type (sqli, xss, ssrf, idor, ...). Falls
            back to info_disclosure default if unknown.
        requires_auth: True → PR:L. requires_admin → PR:H.
        requires_interaction: True → UI:A (Active victim action).
        oob_only: True → AT:P + AC:H (Attack Requirements present, complex).
        subsequent_impact: "high" → SC:H SI:H SA:H (scope change).
        exploit_maturity: CVSS 4.0 E metric — A (Attacked) / P (PoC) / U
            (Unreported) / X (Not Defined, default).
        env_overrides: optional dict of valid 4.0 metric:value (E, CR, IR,
            AR, MAV, ...). Invalid entries silently dropped.
    """
    evidence = {
        "requires_auth": requires_auth,
        "requires_admin": requires_admin,
        "requires_interaction": requires_interaction,
        "oob_only": oob_only,
        "subsequent_impact": subsequent_impact,
    }
    env = dict(env_overrides or {})
    if exploit_maturity and exploit_maturity != "X":
        env["E"] = exploit_maturity
    try:
        v4 = _cvss4.build_vector(vuln_type, evidence=evidence, env=env)
        parsed = _cvss4.parse_vector(v4)
        mv = _cvss4.macrovector(parsed)
        band = _cvss4.band_from_macrovector(mv)
        v31 = _cvss4.to_cvss31_vector(parsed)
        return {
            "cvss4_vector": v4,
            "cvss4_macrovector": mv,
            "cvss4_band": band,
            "cvss31_vector": v31,
            "note": (
                "cvss4_band is APPROXIMATE — derived from MacroVector "
                "equivalence classes. For exact numeric score, install "
                "the `cvss` pip package and call cvss.CVSS4(vector).base_score."
            ),
        }
    except ValueError as exc:
        return {"error": str(exc), "vuln_type": vuln_type}

async def validate_severity_impl(
    vuln_type: str,
    claimed_severity: str,
    requires_auth: bool = False,
    requires_admin: bool = False,
    requires_interaction: bool = False,
    oob_only: bool = False,
    subsequent_impact: str = "",
) -> dict:
    """Reconcile an operator/advisor severity against the CVSS 4.0 vector math.

    Guardian-CLI prior art — catch inflated (or deflated) severities before
    they reach a report (Rule 14). Builds the CVSS 4.0 vector from the same
    finding-shape flags as compute_cvss, derives the categorical band, and
    compares it to the claimed severity. Returns a match/mismatch verdict
    with the delta so the operator can justify or correct the call.

    Args:
        vuln_type: Vulnerability type (sqli, xss, idor, ...).
        claimed_severity: The severity being asserted (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        requires_auth / requires_admin / requires_interaction / oob_only /
            subsequent_impact: same finding-shape flags as compute_cvss.
    """
    order = {"NONE": 0, "INFO": 0, "INFORMATIONAL": 0, "LOW": 1,
             "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    claimed = claimed_severity.strip().upper()
    if claimed not in order:
        return {"error": f"unknown claimed_severity '{claimed_severity}'",
                "valid": sorted(set(order))}
    evidence = {
        "requires_auth": requires_auth, "requires_admin": requires_admin,
        "requires_interaction": requires_interaction, "oob_only": oob_only,
        "subsequent_impact": subsequent_impact,
    }
    try:
        v4 = _cvss4.build_vector(vuln_type, evidence=evidence, env={})
        band = _cvss4.band_from_macrovector(_cvss4.macrovector(_cvss4.parse_vector(v4)))
    except ValueError as exc:
        return {"error": str(exc), "vuln_type": vuln_type}

    computed = band.strip().upper()
    delta = order[claimed] - order.get(computed, 0)
    if delta == 0:
        verdict, advice = "MATCH", "Claimed severity matches the CVSS band."
    elif delta > 0:
        verdict = "INFLATED"
        advice = (f"Claimed {claimed} is {delta} band(s) above the CVSS-derived "
                  f"{computed}. Justify with chain/impact evidence or lower it (Rule 14).")
    else:
        verdict = "UNDERSTATED"
        advice = (f"Claimed {claimed} is {-delta} band(s) below the CVSS-derived "
                  f"{computed}. Consider raising it if impact supports it.")
    return {
        "vuln_type": vuln_type, "claimed": claimed, "cvss_band": computed,
        "verdict": verdict, "cvss4_vector": v4, "advice": advice,
    }

async def debate_triage_impl(
    vuln_type: str,
    evidence_summary: str = "",
    has_chain: bool = False,
) -> dict:
    """Red/Blue/Judge adversarial triage scaffold — run BEFORE assess_finding on ambiguous findings.

    Guardian-CLI prior art (multi-agent debate cuts FP promotion). Praetor
    tools are deterministic, so this doesn't run three LLMs — it hands the
    calling model a structured debate to reason through: a Red case (why
    it's real), a Blue case seeded with the SPECIFIC false-positive modes
    for THIS class (not generic), and a Judge rubric. Argue both sides, then
    call assess_finding. Purpose: stop plausible-but-wrong findings early.

    Args:
        vuln_type: Vulnerability class (sqli, xss, ssrf, idor, ...).
        evidence_summary: One-line note on the evidence collected so far.
        has_chain: Whether this finding is chained to another for impact.
    """
    vt = vuln_type.strip().lower()
    # Class-specific false-positive modes — the Blue advocate's ammunition.
    fp_modes = {
        "sqli": ["WAF 500 vs true DB error", "generic 500 with no vendor string",
                 "timing noise vs real SLEEP delay (need 3/3 replays)", "reflected input ≠ injection"],
        "xss": ["reflection without executable context", "encoded/escaped on output",
                "self-XSS (victim must paste)", "CSP blocks execution"],
        "ssrf": ["error message ≠ actual request egress", "DNS resolution without connection",
                 "no Collaborator/metadata callback = unproven"],
        "ssti": ["math echo could be a coincidence", "sandboxed engine, no escalation",
                 "reflection ≠ evaluation"],
        "idor": ["accessed own data, not another user's", "object exists but returns 403 body",
                 "predictable ID but no sensitive data returned"],
        "open_redirect": ["redirect stays same-origin", "no chain = NEVER-SUBMIT alone"],
        "cors": ["ACAO reflected but no credentials", "no sensitive data behind it"],
        "rce": ["marker start-tag only, no output = PARTIAL", "error text ≠ command output"],
        "xxe": ["parser error ≠ file read", "no OOB and no in-band content"],
    }
    base_fp = ["not reproducible from scratch", "duplicate of a known finding",
               "anomaly vs baseline unexplained but not a real vuln class"]
    blue = fp_modes.get(vt, []) + base_fp
    red = [
        "State the exact attacker capability this proves (money / account / data / privilege).",
        "Cite the confirming replay index and the class-specific marker (per verify-finding.md).",
        "Confirm the evidence clears the per-class bar, not just an anomaly.",
    ]
    judge = [
        "Does the Red case name a concrete attacker action, or only a theory? (theory → NEEDS MORE EVIDENCE)",
        "Is EACH Blue FP-mode ruled out by captured evidence? Any unresolved → do not confirm yet.",
        "Is severity justified by impact (and chain, if NEVER-SUBMIT class)?",
        "Only if Red survives every Blue point: proceed to assess_finding.",
    ]
    if not has_chain and vt in ("open_redirect", "cors"):
        judge.insert(0, f"⚠ {vt} is NEVER-SUBMIT alone — without a chain this is DO NOT REPORT (Rule 17).")
    return {
        "vuln_type": vt,
        "evidence_summary": evidence_summary,
        "red_advocate": red,
        "blue_advocate": blue,
        "judge_rubric": judge,
        "next": "Reason through all three, then call assess_finding with the honest verdict.",
    }
