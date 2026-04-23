"""Professional pentest report generation with structured sections and platform templates."""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.intel import INTEL_DIR, _intel_path


def _load_intel(domain: str, category: str) -> dict:
    """Load intel data for a domain."""
    path = _intel_path(domain) / f"{category}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _severity_sort_key(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity.upper(), 5)


def _build_executive_summary(findings: list[dict], domain: str, profile: dict) -> str:
    """Build executive summary section."""
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

    # Risk assessment
    if by_sev.get("CRITICAL", 0) > 0:
        lines.append("**Overall risk: CRITICAL** — Immediate remediation required for critical findings.")
    elif by_sev.get("HIGH", 0) > 0:
        lines.append("**Overall risk: HIGH** — High-severity findings require prompt attention.")
    elif by_sev.get("MEDIUM", 0) > 0:
        lines.append("**Overall risk: MEDIUM** — Medium-severity findings should be addressed in next sprint.")
    else:
        lines.append("**Overall risk: LOW** — No high-impact findings. Consider hardening recommendations.")

    return "\n".join(lines)


def _build_finding_section(finding: dict, index: int) -> str:
    """Build a single finding section."""
    lines = [
        f"### {index}. [{finding.get('severity', 'INFO')}] {finding.get('vulnerability_type', finding.get('title', 'Finding'))}",
        "",
    ]

    endpoint = finding.get("endpoint", "")
    if endpoint:
        lines.append(f"**Endpoint:** `{endpoint}`")

    param = finding.get("parameter", "")
    if param:
        lines.append(f"**Parameter:** `{param}`")

    status = finding.get("status", "suspected")
    lines.append(f"**Status:** {status}")
    lines.append("")

    desc = finding.get("description", "")
    if desc:
        lines.append(desc)
        lines.append("")

    impact = finding.get("impact", "")
    if impact:
        lines.append(f"**Impact:** {impact}")
        lines.append("")

    evidence = finding.get("evidence", {})
    if evidence:
        lines.append("**Evidence:**")
        if isinstance(evidence, dict):
            for k, v in evidence.items():
                lines.append(f"- {k}: `{str(v)[:200]}`")
        elif isinstance(evidence, str):
            lines.append(f"```\n{evidence[:500]}\n```")
        lines.append("")

    poc = finding.get("poc_request", {})
    if poc:
        lines.append("**PoC Request:**")
        if isinstance(poc, dict):
            method = poc.get("method", "GET")
            path = poc.get("path", "/")
            lines.append(f"```http\n{method} {path}")
            for k, v in poc.get("headers", {}).items():
                lines.append(f"{k}: {v}")
            body = poc.get("body", "")
            if body:
                lines.append(f"\n{body}")
            lines.append("```")
        elif isinstance(poc, str):
            lines.append(f"```\n{poc[:500]}\n```")
        lines.append("")

    chain = finding.get("chain", [])
    if chain:
        lines.append("**Exploit Chain:**")
        for step in chain:
            lines.append(f"  {step.get('step', '?')}. {step.get('description', '')}")
        lines.append("")

    return "\n".join(lines)


def _build_methodology_section() -> str:
    """Build methodology section."""
    return """## Methodology

Testing followed a systematic approach:

1. **Reconnaissance** — Attack surface mapping, technology detection, JavaScript analysis
2. **Vulnerability Testing** — Knowledge-driven probing across 25 vulnerability categories with server-side matchers
3. **Verification** — All findings reproduced with evidence (timing, Collaborator callbacks, error strings)
4. **Impact Assessment** — CVSS 3.1 scoring with real-world impact evaluation
5. **Documentation** — Detailed PoC requests and reproduction steps for each finding

Tools used: Burp Suite Professional via Swiss Knife MCP integration with Claude Code."""


def _build_coverage_section(coverage: dict) -> str:
    """Build test coverage section."""
    entries = coverage.get("entries", [])
    if not entries:
        return ""

    by_category: dict[str, int] = {}
    for e in entries:
        cats = e.get("categories_tested", [])
        for c in cats:
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


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_report(
        domain: str,
        format: str = "pentest",
        platform: str = "",
        include_coverage: bool = True,
    ) -> str:
        """Generate a professional pentest report from saved findings and intel.

        Produces structured reports with executive summary, methodology, findings
        (sorted by severity), coverage statistics, and recommendations.

        Args:
            domain: Target domain to generate report for
            format: 'pentest' (full structured report), 'executive' (summary only), 'findings' (findings list only)
            platform: Bug bounty platform template: 'hackerone', 'bugcrowd', 'intigriti', 'immunefi', or '' for generic
            include_coverage: Include test coverage section (default: true)
        """
        findings_data = _load_intel(domain, "findings")
        profile = _load_intel(domain, "profile")
        coverage = _load_intel(domain, "coverage") if include_coverage else {}

        findings = findings_data.get("findings", [])

        # Merge findings from Burp's in-memory store (volatile, lost on restart)
        burp_data = await client.get("/api/notes/findings")
        if "error" not in burp_data:
            for jf in burp_data.get("findings", []):
                # Avoid duplicates: check if same endpoint+title already in persistent findings
                if not any(
                    f.get("endpoint") == jf.get("endpoint") and
                    (f.get("title") == jf.get("title") or f.get("vulnerability_type") == jf.get("title"))
                    for f in findings
                ):
                    findings.append(jf)

        if not findings:
            return f"No findings saved for {domain}. Use save_finding or save_target_intel to record findings first."

        # Sort by severity
        findings.sort(key=lambda f: _severity_sort_key(f.get("severity", "INFO")))

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Platform-specific single-finding format
        if platform and len(findings) == 1:
            return _format_platform_finding(findings[0], platform, domain)

        # Full report
        sections = []

        if format in ("pentest", "executive"):
            sections.append(f"# Security Assessment Report: {domain}")
            sections.append(f"**Date:** {now}")
            sections.append("")
            sections.append(_build_executive_summary(findings, domain, profile))

        if format == "executive":
            return "\n".join(sections)

        if format == "pentest":
            sections.append("")
            sections.append(_build_methodology_section())

        sections.append("")
        sections.append("## Findings")
        sections.append("")

        for i, finding in enumerate(findings, 1):
            sections.append(_build_finding_section(finding, i))

        if include_coverage and coverage:
            sections.append(_build_coverage_section(coverage))

        if format == "pentest":
            sections.append("")
            sections.append("## Recommendations")
            sections.append("")
            sections.append("1. Address CRITICAL and HIGH findings immediately")
            sections.append("2. Schedule MEDIUM findings for the next development sprint")
            sections.append("3. Review LOW/INFO findings during regular security reviews")
            sections.append("4. Re-test after remediation to verify fixes")
            sections.append("")
            sections.append("---")
            sections.append(f"*Generated by Burp Suite Swiss Knife MCP — {now}*")

        return "\n".join(sections)

    @mcp.tool()
    async def format_finding_for_platform(
        domain: str,
        finding_id: str,
        platform: str,
    ) -> str:
        """Format a specific finding for a bug bounty platform.

        Takes a saved finding and outputs it in the exact format expected by
        HackerOne, Bugcrowd, Intigriti, or Immunefi.

        Args:
            domain: Target domain
            finding_id: Finding ID (e.g. 'f001') from save_target_intel findings
            platform: Platform name: 'hackerone', 'bugcrowd', 'intigriti', 'immunefi'
        """
        findings_data = _load_intel(domain, "findings")
        findings = findings_data.get("findings", [])

        finding = None
        for f in findings:
            if f.get("id") == finding_id:
                finding = f
                break

        if not finding:
            return f"Finding {finding_id} not found for {domain}. Available: {[f.get('id') for f in findings[:10]]}"

        return _format_platform_finding(finding, platform, domain)


# Severity caps for vulnerability classes that are informative at best
# (hunting.md NEVER SUBMIT list + low-impact classes). A hunter can still
# submit if they've escalated via chain-findings, but the solo report severity
# is capped so the triager sees an honest label.
_SEVERITY_CAPS = {
    # key (substring of vuln_type/title) → max allowed severity
    "clickjacking": "LOW",
    "missing security header": "INFO",
    "missing header": "INFO",
    "cookie flag": "INFO",
    "cookie without secure": "INFO",
    "cookie without httponly": "INFO",
    "csrf on logout": "INFO",
    "csrf on non-state": "INFO",
    "mixed content": "INFO",
    "rate limit": "LOW",
    "stack trace": "LOW",
    "information disclosure": "LOW",
    "info disclosure": "LOW",
    "user enumeration": "LOW",
    "username enumeration": "LOW",
    "email enumeration": "LOW",
    "referrer-policy": "INFO",
    "spf": "INFO",
    "dmarc": "INFO",
    "dkim": "INFO",
    "content spoofing": "LOW",
    "text injection": "INFO",
    "self-xss": "INFO",
    "self xss": "INFO",
    "tabnabbing": "INFO",
    "autocomplete": "INFO",
    "options method": "INFO",
    "version disclosure": "LOW",
    "idn homograph": "INFO",
    "open redirect": "MEDIUM",   # LOW unless chained; MEDIUM if chain evidence present
}

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _honest_severity(claimed: str, vuln_type: str, title: str, evidence: str, impact: str) -> tuple[str, str]:
    """Return (capped_severity, note). Honest-severity enforcement per rule 21.

    Compares the claimed severity against a cap table keyed on vuln class.
    If the finding shows chain evidence ("chained with", "escalated via"),
    the cap is relaxed one step.
    """
    claimed_up = (claimed or "MEDIUM").upper()
    if claimed_up not in _SEVERITY_RANK:
        claimed_up = "MEDIUM"

    haystack = f"{vuln_type} {title}".lower()
    chain_hint = any(w in f"{evidence} {impact}".lower() for w in
                     ("chained with", "escalated via", "chain ->", "chain to", "→ account takeover"))

    for key, cap in _SEVERITY_CAPS.items():
        if key in haystack:
            cap_up = cap
            if chain_hint:
                # Relax one step when chained
                ranks = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                cap_up = ranks[min(ranks.index(cap) + 1, 4)]
            if _SEVERITY_RANK[claimed_up] > _SEVERITY_RANK[cap_up]:
                note = f"Severity capped at {cap_up} ({key} alone is informative; requested {claimed_up})"
                return cap_up, note
            return claimed_up, ""
    return claimed_up, ""


def _cvss_vector(severity: str) -> str:
    """Return a reasonable CVSS 3.1 vector hint for each severity band."""
    sev = severity.upper()
    # Generic vectors — the reporter should replace with target-specific metrics
    if sev == "CRITICAL":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if sev == "HIGH":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if sev == "MEDIUM":
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    if sev == "LOW":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    return "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"


def _format_platform_finding(finding: dict, platform: str, domain: str) -> str:
    """Format a single finding for a specific platform."""
    vuln_type = finding.get("vulnerability_type", finding.get("title", "Vulnerability"))
    endpoint = finding.get("endpoint", "/")
    description = finding.get("description", "")
    impact = finding.get("impact", "")
    evidence = finding.get("evidence", {})
    poc = finding.get("poc_request", {})
    param = finding.get("parameter", "")

    # Honest-severity cap — rule 21 says no inflating. Evidence-driven CVSS.
    severity, severity_note = _honest_severity(
        finding.get("severity", "MEDIUM"),
        vuln_type,
        finding.get("title", ""),
        evidence if isinstance(evidence, str) else str(evidence),
        impact,
    )
    cvss_vector = _cvss_vector(severity)

    # Build PoC steps
    poc_steps = ""
    if isinstance(poc, dict):
        method = poc.get("method", "GET")
        path = poc.get("path", endpoint)
        headers = poc.get("headers", {})
        body = poc.get("body", "")
        poc_steps = f"1. Send the following request:\n```http\n{method} {path} HTTP/1.1\nHost: {domain}\n"
        for k, v in headers.items():
            poc_steps += f"{k}: {v}\n"
        if body:
            poc_steps += f"\n{body}\n"
        poc_steps += "```\n"
        expected = poc.get("expected_behavior", "")
        if expected:
            poc_steps += f"2. Observe: {expected}\n"
    elif isinstance(poc, str):
        poc_steps = poc

    evidence_str = ""
    if isinstance(evidence, dict):
        evidence_str = "\n".join(f"- {k}: {v}" for k, v in evidence.items())
    elif isinstance(evidence, str):
        evidence_str = evidence

    platform = platform.lower()

    if platform == "hackerone":
        return f"""## Summary
{vuln_type} in `{endpoint}` on {domain} allows an attacker to {impact or 'access unauthorized resources'}.

## Steps to Reproduce
{poc_steps or f'1. Navigate to {endpoint}\n2. [Steps needed]'}

## Impact
{impact or description}

## Supporting Material/References
{evidence_str}
- Severity: {severity}
- CVSS vector (edit to match): {cvss_vector}
- Parameter: {param}
{f'- Note: {severity_note}' if severity_note else ''}"""

    elif platform == "bugcrowd":
        return f"""## Title
{vuln_type} in {endpoint} — {impact or severity}

## Description
{description or f'{vuln_type} was discovered in {endpoint} on {domain}.'}

## Proof of Concept
### Environment
- URL: https://{domain}{endpoint}
- Auth state: [specify authentication state]

### Steps
{poc_steps or '1. [Steps needed]'}

### Expected vs Actual
- Expected: Request is handled securely
- Actual: {impact or 'Vulnerability is exploitable'}

## Impact Statement
{impact or description}

## CVSS
Severity: {severity}
Vector (edit to match your target): {cvss_vector}

## Attachments
{evidence_str}

{f'_Note: {severity_note}_' if severity_note else ''}"""

    elif platform == "intigriti":
        return f"""## Vulnerability Type
{vuln_type}

## Domain/URL
https://{domain}{endpoint}

## Summary
{description or f'{vuln_type} found in {endpoint}'}

## Steps to Reproduce
{poc_steps or '1. [Steps needed]'}

## Impact
{impact or description}
Severity: {severity}

## CVSS 3.1
Severity: {severity}
Vector String (edit to match your target): {cvss_vector}

## Proof
{evidence_str}

{f'_Note: {severity_note}_' if severity_note else ''}"""

    elif platform == "immunefi":
        return f"""## Bug Description
{description or f'{vuln_type} discovered in {endpoint} on {domain}'}

## Impact
{impact or 'Describe the concrete impact on the protocol'}

## Risk Breakdown
Difficulty to Exploit: [Easy/Medium/Hard]

## Proof of Concept
{poc_steps or '1. [Steps needed]'}

## Recommendation
[Provide remediation guidance]"""

    else:
        return f"""# {vuln_type}

**Target:** {domain}
**Endpoint:** {endpoint}
**Parameter:** {param}
**Severity:** {severity}
**Status:** {finding.get('status', 'suspected')}

## Description
{description}

## Impact
{impact}

## Proof of Concept
{poc_steps}

## Evidence
{evidence_str}"""
