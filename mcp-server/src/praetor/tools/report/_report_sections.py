"""Report-level sections: executive summary, methodology, coverage."""

from praetor.tools.report.business_logic_gate import business_logic_gate

_TIMELINE_MAP: dict[str, str] = {
    "CRITICAL": "Immediate",
    "HIGH": "< 7 days",
    "MEDIUM": "< 30 days",
    "LOW": "< 90 days",
    "INFO": "Ongoing",
}


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

    lines.append("")

    # ── Remediation priority table
    lines.append("### Remediation Priority")
    lines.append("")
    lines.append("| ID | Finding | Severity | Timeline | Business Risk |")
    lines.append("|---|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO").upper()
        title = f.get("title") or f.get("vulnerability_type", "Finding")
        if len(title) > 50:
            title = title[:47] + "..."
        timeline = _TIMELINE_MAP.get(sev, "Ongoing")
        impact = f.get("impact", "")
        if isinstance(impact, list):
            impact = impact[0] if impact else ""
        if len(str(impact)) > 60:
            impact = str(impact)[:57] + "..."
        fid = f.get("id", f"F{i:03d}")
        lines.append(f"| {fid} | {title} | {sev} | {timeline} | {impact} |")
    lines.append("")

    return "\n".join(lines)


def build_limitations_section(limitations: list[str] | None = None) -> str:
    """Assessment limitations section."""
    lines = ["## Limitations", ""]
    lines.append(
        "The following areas were outside the scope of this assessment "
        "or could not be tested due to missing prerequisites:"
    )
    lines.append("")
    defaults = [
        "**Authenticated application testing:** No valid credentials were provided unless stated otherwise. Authenticated attack surface (IDOR, BFLA, business logic, privilege escalation) was tested only where credentials were available.",
        "**Internal network:** The assessment covered only publicly accessible infrastructure. Internal services behind VPN, firewall, or ZTNA were not tested.",
        "**Mobile applications:** No mobile applications were included in scope unless stated otherwise.",
        "**Source code review:** No source code access was provided. All testing was black-box unless stated otherwise.",
        "**Denial of service:** Intentional DoS testing was excluded to avoid disruption to production services.",
        "**Social engineering:** Phishing, vishing, and physical access testing were excluded.",
    ]
    items = limitations if limitations else defaults
    for item in items:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(
        "_The findings in this report reflect vulnerabilities identified during the "
        "assessment window. The target environment may have changed since the assessment._"
    )
    lines.append("")
    return "\n".join(lines)


def build_standards_mapping(findings: list[dict]) -> str:
    """OWASP / CWE / WSTG reference mapping table."""
    from praetor.tools._framework_map import framework_tags

    lines = ["## Standards Mapping", ""]
    lines.append(
        "Each finding is mapped to industry standard classifications for tracking and compliance:"
    )
    lines.append("")
    lines.append("| ID | CWE | OWASP Category | WSTG Reference |")
    lines.append("|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        fid = f.get("id", f"F{i:03d}")
        cwe = f.get("cwe", "")
        owasp = f.get("owasp", "")
        fw = framework_tags(f.get("vuln_type") or f.get("vulnerability_type", ""))
        if not cwe:
            cwe = fw.get("cwe", "-")
        if not owasp:
            owasp = fw.get("owasp", "-")
        wstg = fw.get("wstg", "-")
        lines.append(f"| {fid} | {cwe} | {owasp} | {wstg} |")
    lines.append("")
    return "\n".join(lines)


def build_glossary(terms: dict[str, str] | None = None) -> str:
    """Glossary of technical terms for non-technical readers."""
    defaults = {
        "API (Application Programming Interface)": "A way for software applications to communicate with each other. An API key is a password-like string that grants access to an API.",
        "Authentication": "The process of verifying the identity of a user or system. 'Unauthenticated' means no identity verification is required.",
        "Brute Force": "An attack method that tries every possible combination until the correct one is found.",
        "CORS (Cross-Origin Resource Sharing)": "A browser security mechanism that controls which websites can make requests to an API.",
        "CVSS (Common Vulnerability Scoring System)": "An industry-standard framework for rating the severity of security vulnerabilities on a scale from 0.0 to 10.0.",
        "CVE (Common Vulnerabilities and Exposures)": "A unique identifier assigned to a publicly known security vulnerability.",
        "CWE (Common Weakness Enumeration)": "A classification system for the type of software weakness that causes a vulnerability.",
        "LLM (Large Language Model)": "An artificial intelligence system that processes and generates natural language text.",
        "OAuth": "A protocol that allows users to grant applications access to their accounts without sharing their password.",
        "OTP (One-Time Password)": "A temporary code sent via email or SMS that expires after a single use or short time period.",
        "PII (Personally Identifiable Information)": "Data that can identify a specific individual, such as full name, email address, or profile URL.",
        "Rate Limiting": "A security control that restricts how many requests a user can make in a given time period.",
        "Stored XSS (Cross-Site Scripting)": "An attack where malicious code is stored on a server and executed in every visitor's browser that views the affected page.",
        "X-Forwarded-For": "An HTTP header that identifies the original IP address of a client connecting through a proxy or load balancer.",
    }
    items = terms if terms else defaults
    lines = ["## Glossary", ""]
    lines.append("Technical terms used in this report:")
    lines.append("")
    for term, definition in items.items():
        lines.append(f"**{term}**")
        lines.append(f": {definition}")
        lines.append("")
    return "\n".join(lines)


def build_disclaimer() -> str:
    """Confidentiality and disclaimer section."""
    return """## Disclaimer

This report is provided on a confidential basis to the intended recipient only. The findings and recommendations contained herein are based on the assessment conducted on the date specified and reflect the state of the target environment at that time.

The assessment was performed using non-destructive testing techniques. Where write operations were required to verify impact, the test data was cleaned up immediately after verification.

This report does not guarantee the absence of additional vulnerabilities beyond those identified during the assessment. The scope was limited to the testing described in the Methodology section.

The recipient is responsible for evaluating the findings, determining the appropriate remediation actions, and implementing them in a timeline consistent with the organization's risk appetite.

**Distribution:** This document is classified CONFIDENTIAL. Do not distribute outside the authorized recipient list without written approval."""



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
    techs: set = set()
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
        techs |= {(o.get("technique"), o.get("technique_name"))
                  for o in ops if o.get("technique")}
        detected = sum(1 for o in ops if o.get("detected"))
        lines.append(f"_Stealth: {detected} of {len(ops)} recorded actions were detected._")
        lines.append("")

    confirmed = [f for f in findings if str(f.get("status", "")).lower() == "confirmed"]

    # Enrich the ATT&CK view from confirmed findings too (framework_tags carries
    # attack_ck per vuln class), so techniques surface even when the oplog is thin.
    try:
        from praetor.tools._framework_map import framework_tags
        for f in confirmed:
            row = framework_tags(f.get("vuln_type") or f.get("title", ""))
            name = row.get("attack_name", "")
            for tid in row.get("attack_ck", []) or []:
                techs.add((tid, name))
    except Exception:
        pass
    if techs:
        lines.append("### MITRE ATT&CK techniques observed")
        for tid, tname in sorted(t for t in techs if t[0]):
            lines.append(f"- {tid} {tname}".rstrip())
        lines.append("")

    lines.append(f"### Objective Impact ({len(confirmed)} confirmed)")
    if not confirmed:
        lines.append("_No confirmed objective impact recorded._")
    for f in confirmed[:25]:
        lines.append(f"- [{f.get('severity', '?')}] {f.get('title', '')} @ {f.get('endpoint', '')}")
    return "\n".join(lines)
