"""Report-level sections: executive summary, methodology, coverage."""

from praetor.tools.report.business_logic_gate import business_logic_gate

def build_executive_summary(
    findings: list[dict], domain: str, profile: dict, internal: bool = False
) -> str:
    by_sev: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    total = len(findings)
    tech = profile.get("tech_stack", [])

    noun = "finding" if total == 1 else "findings"
    lines: list[str] = []

    # W36-P1: business-logic completion gate. Operator-only warning (not client
    # content) — surfaces at the top when the business-logic pass is unproven.
    # Never blocks; disappears once one invariant is recorded as tested.
    bl_warning = business_logic_gate(domain) if internal else ""
    if bl_warning:
        lines += [
            f"> **Operator note (remove before client delivery):** {bl_warning}",
            "",
        ]

    lines += [
        "## Executive Summary",
        "",
        f"Security assessment of **{domain}** identified **{total} {noun}**.",
        "",
    ]

    if by_sev:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_sev:
                lines.append(f"| {sev} | {by_sev[sev]} |")
        lines.append("")

    if tech:
        lines.append(f"**Technology stack:** {', '.join(tech[:10])}")
        lines.append("")

    if by_sev.get("CRITICAL", 0) > 0:
        lines.append("**Overall risk: CRITICAL** — Immediate remediation required for critical findings.")
    elif by_sev.get("HIGH", 0) > 0:
        lines.append("**Overall risk: HIGH** — High-severity findings require prompt attention.")
    elif by_sev.get("MEDIUM", 0) > 0:
        lines.append("**Overall risk: MEDIUM** — Medium-severity findings should be addressed in next sprint.")
    else:
        lines.append("**Overall risk: LOW** — No high-impact findings. Consider hardening recommendations.")

    return "\n".join(lines)



def build_methodology_section() -> str:
    """Methodology section aligned with PTES, OWASP WSTG v4.2, NIST SP 800-115, OSSTMM 3.0."""
    return """## Methodology

This assessment followed PTES (Penetration Testing Execution Standard), OWASP
WSTG v4.2, and NIST SP 800-115 guidance. Testing was conducted from an
unauthenticated and authenticated perspective where credentials were provided.

1. **Intelligence Gathering / Reconnaissance** — Passive and active attack
   surface mapping: subdomain enumeration (CT logs, DNS, Wayback), technology
   fingerprinting, JavaScript analysis (TruffleHog/Gitleaks-quality secret
   scanning, DOM sink/source inventory), endpoint discovery, hidden parameter
   discovery.
2. **Threat Modelling** — Per-endpoint risk scoring informed by parameter
   names, auth state, and detected tech stack. Priority categories selected
   based on framework-implied bug classes (e.g. prototype pollution on
   Node, deserialization on Java, mass assignment on Rails).
3. **Vulnerability Analysis** — Knowledge-driven probing across the OWASP
   Top 10 2021 and API Top 10 2023 classes with server-side matchers tuned
   for low false-positive rates. Manual testing for business-logic flaws,
   race conditions, IDOR matrices, and chained exploits.
4. **Exploitation** — Each reported finding verified by reproducible PoC
   request and baseline-vs-anomaly comparison. Blind and timing classes were
   held to repeated independent replays; out-of-band confirmation via Burp
   Collaborator for blind SQLi, SSRF, RCE, XXE, and deserialization.
5. **Post-Exploitation / Impact Assessment** — Concrete attacker walkthrough
   (privilege escalation, lateral movement, data exfiltration potential),
   CVSS 4.0 scoring with target-specific metrics (calculator:
   https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator), MITRE ATT&CK
   technique mapping where applicable.
6. **Reporting** — Executive summary, per-finding technical detail (Context,
   Vulnerability, Walkthrough, Impact, Escalation, PoC, Reproduction Steps,
   Evidence, Remediation, References), and prioritised remediation roadmap.

**Tooling:** Burp Suite Professional (intercepting proxy, scanner, repeater,
intruder, collaborator) with supplementary external recon tooling (subfinder,
nuclei, katana, ffuf, dalfox, sqlmap) routed through the Burp proxy for full
traffic capture.

**Scope discipline:** All testing constrained to the program's declared scope.
Destructive payloads (DROP, DELETE, TRUNCATE, rm -rf), credential brute-force,
and modification of other users' data were explicitly excluded. Blind testing
preferred Collaborator over visible side effects."""


def build_coverage_section(coverage: dict, internal: bool = False) -> str:
    """Coverage matrix.

    Rule 16a: request tallies and parameter counts measure effort, not risk,
    and read as padding to a triager or client. The client-facing version names
    which classes were exercised; the counts stay in the internal artifact.
    """
    entries = coverage.get("entries", [])
    if not entries:
        return ""

    by_category: dict[str, int] = {}
    for e in entries:
        for c in e.get("categories_tested", []):
            by_category[c] = by_category.get(c, 0) + 1

    lines = ["## Test Coverage", ""]
    if internal:
        lines.append(f"**Total parameters tested:** {len(entries)}")
        lines.append(f"**Knowledge base version:** {coverage.get('knowledge_version', 'unknown')}")
        lines.append("")

    if by_category:
        if internal:
            lines.append("| Category | Parameters Tested |")
            lines.append("|----------|------------------|")
            for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
                lines.append(f"| {cat} | {count} |")
        else:
            lines.append("Vulnerability classes exercised against the in-scope surface:")
            lines.append("")
            for cat in sorted(by_category):
                lines.append(f"- {cat}")
        lines.append("")

    return "\n".join(lines)


# ATT&CK tactics in kill-chain order for the red-team narrative.
_KILLCHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def build_killchain_section(domain: str, findings: list, *, internal: bool = False) -> str:
    """Red-team kill-chain narrative from the ATT&CK-tagged operator log + findings.

    Pure-ish (reads the on-disk operator log). Groups actions by ATT&CK tactic in
    kill-chain order, lists the techniques observed, flags detected steps, and ends
    with the confirmed-finding impact — the deliverable a red-team engagement needs
    instead of a CVSS-sorted finding list.
    """
    try:
        from praetor.tools.redteam._oplog import read_oplog
        ops = read_oplog(domain)
    except Exception:
        ops = []
    lines = ["## Attack Narrative (Kill Chain)", ""]
    if not ops:
        lines.append("_No operator-log actions recorded yet — use `record_redteam_action` "
                     "so each step is ATT&CK-tagged and this narrative builds itself._")
    else:
        by_tactic: dict[str, list] = {}
        for o in ops:
            by_tactic.setdefault(o.get("tactic") or "Uncategorized", []).append(o)
        order = _KILLCHAIN_ORDER + [t for t in by_tactic if t not in _KILLCHAIN_ORDER]
        for tac in order:
            acts = by_tactic.get(tac)
            if not acts:
                continue
            lines.append(f"### {tac}")
            for o in sorted(acts, key=lambda x: x.get("seq", 0)):
                tech = o.get("technique", "")
                tname = o.get("technique_name", "")
                det = " [DETECTED]" if o.get("detected") else ""
                tgt = o.get("target", "")
                desc = o.get("description") or o.get("tool", "")
                head = f"{tech} {tname}".strip()
                lines.append(f"- {head} — {desc}" + (f" on {tgt}" if tgt else "") + det)
            lines.append("")
        techs = sorted({(o.get("technique"), o.get("technique_name"))
                        for o in ops if o.get("technique")})
        if techs:
            lines.append("### MITRE ATT&CK techniques observed")
            for tid, tname in techs:
                lines.append(f"- {tid} {tname}".rstrip())
            lines.append("")
        detected = sum(1 for o in ops if o.get("detected"))
        lines.append(f"_Stealth: {detected} of {len(ops)} recorded actions were detected._")
        lines.append("")

    confirmed = [f for f in findings if str(f.get("status", "")).lower() == "confirmed"]
    lines.append(f"### Objective Impact ({len(confirmed)} confirmed)")
    if not confirmed:
        lines.append("_No confirmed objective impact recorded._")
    for f in confirmed[:25]:
        lines.append(f"- [{f.get('severity', '?')}] {f.get('title', '')} @ {f.get('endpoint', '')}")
    return "\n".join(lines)
