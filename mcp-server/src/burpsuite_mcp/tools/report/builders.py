"""Markdown section builders for the pentest report.

Layout follows PTES §7 (Reporting), OWASP WSTG v4.2, NIST SP 800-115:
  Classification → Context → Vulnerability → Walkthrough → Impact →
  Escalation → PoC → Reproduction → Evidence → Remediation → References
"""


def format_poc_request(poc) -> str:
    """Render a poc_request dict (or string) as an http code block."""
    if isinstance(poc, dict):
        method = poc.get("method", "GET")
        path = poc.get("path", "/")
        host = poc.get("host", "")
        out = ["```http", f"{method} {path} HTTP/1.1"]
        if host:
            out.append(f"Host: {host}")
        for k, v in poc.get("headers", {}).items():
            out.append(f"{k}: {v}")
        body = poc.get("body", "")
        if body:
            out.append("")
            out.append(str(body))
        out.append("```")
        return "\n".join(out)
    if isinstance(poc, str) and poc.strip():
        return f"```\n{poc[:1500]}\n```"
    return ""


def format_repro_steps(steps) -> str:
    """Render reproduction steps. Accepts list[str] | list[dict] | str."""
    if isinstance(steps, list):
        out = []
        for i, s in enumerate(steps, 1):
            if isinstance(s, dict):
                desc = s.get("step") or s.get("description") or str(s)
                expected = s.get("expected", "")
                out.append(f"{i}. {desc}")
                if expected:
                    out.append(f"   - Expected: {expected}")
            else:
                out.append(f"{i}. {s}")
        return "\n".join(out)
    if isinstance(steps, str) and steps.strip():
        return steps
    return ""


def build_executive_summary(findings: list[dict], domain: str, profile: dict) -> str:
    by_sev: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    total = len(findings)
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    tech = profile.get("tech_stack", [])

    lines = [
        "## Executive Summary",
        "",
        f"Security assessment of **{domain}** identified **{total} findings** "
        f"({confirmed} confirmed).",
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


def build_finding_section(finding: dict, index: int) -> str:
    """Build a single finding section to professional pentest standard."""
    title = finding.get("vulnerability_type") or finding.get("title", "Finding")
    severity = finding.get("severity", "INFO")
    lines = [f"### {index}. [{severity}] {title}", ""]

    # ── Classification
    endpoint = finding.get("endpoint", "")
    param = finding.get("parameter", "")
    status = finding.get("status", "suspected")
    confidence = finding.get("confidence")
    cwe = finding.get("cwe", "")
    owasp = finding.get("owasp", "")
    cvss = finding.get("cvss_vector") or finding.get("cvss", "")
    vuln_type = finding.get("vulnerability_type") or finding.get("vuln_type", "")

    lines.append("**Classification**")
    if vuln_type:
        lines.append(f"- Vulnerability class: `{vuln_type}`")
    if endpoint:
        lines.append(f"- Endpoint: `{endpoint}`")
    if param:
        lines.append(f"- Parameter / injection point: `{param}`")
    if cwe:
        lines.append(f"- CWE: {cwe}")
    if owasp:
        lines.append(f"- OWASP Top 10: {owasp}")
    if cvss:
        lines.append(f"- CVSS 4.0 vector: `{cvss}`")
    lines.append(f"- Severity: **{severity}**")
    lines.append(f"- Status: `{status}`")
    if isinstance(confidence, (int, float)):
        pct = int(round(confidence * 100))
        band = (
            "Confirmed" if confidence >= 0.90 else
            "Strong suspicion" if confidence >= 0.60 else
            "Weak signal" if confidence >= 0.30 else
            "Informational"
        )
        lines.append(f"- Confidence: {pct}% ({band})")
    lines.append("")

    # ── Context
    context = finding.get("context", "")
    if context:
        lines.append("**Context**")
        lines.append(context)
        lines.append("")

    # ── Vulnerability
    desc = finding.get("description", "")
    if desc:
        lines.append("**Vulnerability**")
        lines.append(desc)
        lines.append("")

    # ── Attack walkthrough
    walkthrough = finding.get("attack_walkthrough") or finding.get("walkthrough", "")
    if walkthrough:
        lines.append("**Attack Walkthrough**")
        if isinstance(walkthrough, list):
            for i, step in enumerate(walkthrough, 1):
                if isinstance(step, dict):
                    lines.append(f"{i}. {step.get('description') or step.get('step', '')}")
                else:
                    lines.append(f"{i}. {step}")
        else:
            lines.append(str(walkthrough))
        lines.append("")

    # ── Impact
    impact = finding.get("impact", "")
    if impact:
        lines.append("**Impact**")
        lines.append(impact)
        lines.append("")

    # ── Escalation
    escalation = finding.get("escalation", "")
    chain = finding.get("chain") or finding.get("chain_with") or []
    if escalation or chain:
        lines.append("**Escalation Path**")
        if escalation:
            lines.append(escalation)
        if chain:
            for step in chain:
                if isinstance(step, dict):
                    lines.append(f"- step {step.get('step', '?')}: {step.get('description', '')}")
                else:
                    lines.append(f"- chained with finding `{step}`")
        lines.append("")

    # ── Proof of Concept
    poc = finding.get("poc_request", {})
    poc_block = format_poc_request(poc)
    if poc_block:
        lines.append("**Proof of Concept**")
        lines.append(poc_block)
        lines.append("")

    # ── Reproduction
    repro = finding.get("reproduction_steps") or finding.get("reproduction") or finding.get("steps_to_reproduce", "")
    repro_block = format_repro_steps(repro)
    if repro_block:
        lines.append("**Steps to Reproduce (cold start)**")
        lines.append(repro_block)
        lines.append("")

    # ── Evidence
    evidence = finding.get("evidence", {})
    evidence_text = finding.get("evidence_text", "")
    reproductions = finding.get("reproductions", []) or []
    if evidence or evidence_text or reproductions:
        lines.append("**Evidence**")
        if isinstance(evidence, dict):
            for k, v in evidence.items():
                lines.append(f"- {k}: `{str(v)[:200]}`")
        elif isinstance(evidence, str) and evidence.strip():
            lines.append(f"```\n{evidence[:800]}\n```")
        if reproductions:
            lines.append("")
            lines.append("Replays (timing/blind reproductions):")
            lines.append("")
            lines.append("| # | logger_index | status | elapsed_ms |")
            lines.append("|---|---|---|---|")
            for i, r in enumerate(reproductions, 1):
                if isinstance(r, dict):
                    lines.append(
                        f"| {i} | {r.get('logger_index', '?')} | "
                        f"{r.get('status_code', '?')} | {r.get('elapsed_ms', '?')} |"
                    )
        if evidence_text and evidence_text.strip():
            lines.append("")
            lines.append("```")
            lines.append(evidence_text[:1500])
            lines.append("```")
        lines.append("")

    # ── Remediation
    remediation = finding.get("remediation") or finding.get("recommendation", "")
    if remediation:
        lines.append("**Remediation**")
        if isinstance(remediation, list):
            for r in remediation:
                lines.append(f"- {r}")
        else:
            lines.append(str(remediation))
        lines.append("")

    # ── References
    refs = finding.get("references", [])
    if refs:
        lines.append("**References**")
        if isinstance(refs, list):
            for r in refs:
                lines.append(f"- {r}")
        else:
            lines.append(str(refs))
        lines.append("")

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
3. **Vulnerability Analysis** — Knowledge-driven probing across 25+
   vulnerability categories (OWASP Top 10 2021 + API Top 10 2023) with
   server-side matchers tuned for low false-positive rates. Manual testing
   for business-logic flaws, race conditions, IDOR matrices, and chained
   exploits.
4. **Exploitation** — Each suspected finding verified by reproducible PoC
   request, baseline-vs-anomaly comparison, and (for blind/timing classes)
   ≥3 consistent replays. Out-of-band confirmation via Burp Collaborator for
   blind SQLi, SSRF, RCE, XXE, and deserialization classes.
5. **Post-Exploitation / Impact Assessment** — Concrete attacker walkthrough
   (privilege escalation, lateral movement, data exfiltration potential),
   CVSS 4.0 scoring with target-specific metrics (calculator:
   https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator), MITRE ATT&CK
   technique mapping where applicable.
6. **Reporting** — Executive summary, per-finding technical detail (Context,
   Vulnerability, Walkthrough, Impact, Escalation, PoC, Reproduction Steps,
   Evidence, Remediation, References), test coverage matrix, and prioritised
   remediation roadmap.

**Tooling:** Burp Suite Professional (intercepting proxy, scanner, repeater,
intruder, collaborator), Burp Suite Swiss Knife MCP integration with Claude
Code (164 MCP tools across 32 modules), supplementary external recon tools
(subfinder, nuclei, katana, ffuf, dalfox, sqlmap) routed through the Burp
proxy for full traffic capture.

**Scope discipline:** All testing constrained to the program's declared scope.
Destructive payloads (DROP, DELETE, TRUNCATE, rm -rf), credential brute-force,
and modification of other users' data were explicitly excluded. Blind testing
preferred Collaborator over visible side effects."""


def build_coverage_section(coverage: dict) -> str:
    entries = coverage.get("entries", [])
    if not entries:
        return ""

    by_category: dict[str, int] = {}
    for e in entries:
        for c in e.get("categories_tested", []):
            by_category[c] = by_category.get(c, 0) + 1

    lines = ["## Test Coverage", ""]
    lines.append(f"**Total parameters tested:** {len(entries)}")
    lines.append(f"**Knowledge base version:** {coverage.get('knowledge_version', 'unknown')}")
    lines.append("")

    if by_category:
        lines.append("| Category | Parameters Tested |")
        lines.append("|----------|------------------|")
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    return "\n".join(lines)
