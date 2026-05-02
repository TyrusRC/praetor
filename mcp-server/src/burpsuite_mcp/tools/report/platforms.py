"""Platform-specific finding formatters: HackerOne, Bugcrowd, Intigriti, Immunefi.

All templates emit the same logical sections (Context, Vulnerability,
Walkthrough, Escalation, PoC, Reproduction, Remediation, References, CVSS 4.0)
but in each platform's preferred order/headers.
"""

from burpsuite_mcp.tools.report.severity import (
    cvss_v4_vector,
    honest_severity,
)


def _list_or_str(value, joiner="\n", item_prefix="") -> str:
    """Render a list field or pass through a string."""
    if isinstance(value, list):
        return joiner.join(f"{item_prefix}{v}" for v in value)
    return str(value or "")


def _numbered(value) -> str:
    """Render a list as a numbered list, or pass through a string."""
    if isinstance(value, list):
        return "\n".join(f"{i}. {s}" for i, s in enumerate(value, 1))
    return str(value or "")


def _evidence_str(evidence) -> str:
    if isinstance(evidence, dict):
        return "\n".join(f"- {k}: {v}" for k, v in evidence.items())
    if isinstance(evidence, str):
        return evidence
    return ""


def _poc_steps(poc, endpoint, domain) -> str:
    """Build a Markdown HTTP block + observation line from a poc_request dict/string."""
    if isinstance(poc, dict):
        method = poc.get("method", "GET")
        path = poc.get("path", endpoint)
        headers = poc.get("headers", {})
        body = poc.get("body", "")
        out = f"1. Send the following request:\n```http\n{method} {path} HTTP/1.1\nHost: {domain}\n"
        for k, v in headers.items():
            out += f"{k}: {v}\n"
        if body:
            out += f"\n{body}\n"
        out += "```\n"
        expected = poc.get("expected_behavior", "")
        if expected:
            out += f"2. Observe: {expected}\n"
        return out
    return str(poc) if poc else ""


def format_platform_finding(finding: dict, platform: str, domain: str) -> str:
    """Format a single finding for a specific bug-bounty platform."""
    vuln_type = finding.get("vulnerability_type", finding.get("title", "Vulnerability"))
    endpoint = finding.get("endpoint", "/")
    description = finding.get("description", "")
    impact = finding.get("impact", "")
    evidence = finding.get("evidence", {})
    poc = finding.get("poc_request", {})
    param = finding.get("parameter", "")

    severity, severity_note = honest_severity(
        finding.get("severity", "MEDIUM"),
        vuln_type,
        finding.get("title", ""),
        evidence if isinstance(evidence, str) else str(evidence),
        impact,
    )
    cvss_vector = cvss_v4_vector(severity)

    confidence = finding.get("confidence")
    conf_line = f"- Confidence: {int(round(confidence * 100))}%" if isinstance(confidence, (int, float)) else ""

    poc_steps = _poc_steps(poc, endpoint, domain)
    evidence_str = _evidence_str(evidence)

    context = finding.get("context", "")
    walkthrough_str = _numbered(finding.get("attack_walkthrough") or finding.get("walkthrough", ""))
    escalation = finding.get("escalation", "")
    reproduction_str = _numbered(finding.get("reproduction_steps") or finding.get("steps_to_reproduce", ""))
    default_repro = (
        f"1. Authenticate (or skip if unauth)\n"
        f"2. Send the request below to https://{domain}{endpoint}\n"
        f"3. Observe the response indicators listed under Evidence"
    )
    note_line = f"- Note: {severity_note}" if severity_note else ""
    remediation_str = _list_or_str(finding.get("remediation") or finding.get("recommendation", ""), item_prefix="- ")
    references_str = _list_or_str(finding.get("references", []), item_prefix="- ")
    cwe = finding.get("cwe", "")
    owasp = finding.get("owasp", "")

    platform = platform.lower()

    if platform == "hackerone":
        return f"""## Summary
{vuln_type} in `{endpoint}` on {domain} allows an attacker to {impact or 'access unauthorized resources'}.

## Context
{context or '_Briefly describe what this endpoint does, who can reach it, and why a vulnerability here matters._'}

## Vulnerability Details
{description or f'{vuln_type} in the `{param}` parameter at `{endpoint}`.'}

## Steps to Reproduce (cold start)
{reproduction_str or poc_steps or default_repro}

## Proof of Concept Request
{poc_steps or '_Insert HTTP request_'}

## Attack Walkthrough — How an attacker exploits this
{walkthrough_str or '_Step-by-step exploitation: discovery → injection → control → impact._'}

## Escalation Path
{escalation or '_How this finding can be chained or escalated for higher impact (account takeover, RCE, lateral movement)._'}

## Impact
{impact or description}

## Remediation
{remediation_str or '_Concrete fix: input validation / output encoding / parameterised queries / least-privilege IAM._'}

## Supporting Material / Evidence
{evidence_str}

## References
{references_str}
- Severity: {severity}
{conf_line}
- CVSS 4.0 vector (edit via https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator): {cvss_vector}
- CWE: {cwe or '_e.g. CWE-89, CWE-79_'}
- OWASP: {owasp or '_e.g. A03:2021-Injection_'}
- Parameter: {param}
{note_line}"""

    if platform == "bugcrowd":
        return f"""## Title
{vuln_type} in {endpoint} — {impact or severity}

## Context
{context or '_Endpoint purpose, auth state, who can reach it._'}

## Description
{description or f'{vuln_type} was discovered in {endpoint} on {domain}.'}

## Proof of Concept
### Environment
- URL: https://{domain}{endpoint}
- Auth state: [specify authentication state]

### PoC Request
{poc_steps or '_Insert HTTP request_'}

### Steps to Reproduce (cold start)
{reproduction_str or '1. [Steps needed]'}

### Expected vs Actual
- Expected: Request is handled securely
- Actual: {impact or 'Vulnerability is exploitable'}

## Attack Walkthrough
{walkthrough_str or '_End-to-end exploit: discovery → trigger → control → impact._'}

## Escalation Path
{escalation or '_How this can be chained: e.g. SSRF → IMDS credentials → S3 takeover; XSS → cookie theft → ATO._'}

## Impact Statement
{impact or description}

## Remediation
{remediation_str or '_Server-side validation, parameterised queries, output encoding, least-privilege IAM._'}

## CVSS 4.0
Severity: {severity}
{conf_line}
Vector (edit via https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator): {cvss_vector}
CWE: {cwe}
OWASP: {owasp}

## Attachments / Evidence
{evidence_str}

## References
{references_str}

{f'_Note: {severity_note}_' if severity_note else ''}"""

    if platform == "intigriti":
        return f"""## Vulnerability Type
{vuln_type}

## Domain/URL
https://{domain}{endpoint}

## Context
{context or '_What this endpoint does and why a vulnerability here matters._'}

## Summary
{description or f'{vuln_type} found in {endpoint}'}

## Proof of Concept Request
{poc_steps or '_Insert HTTP request_'}

## Steps to Reproduce (cold start)
{reproduction_str or '1. [Steps needed]'}

## Attack Walkthrough
{walkthrough_str or '_Step-by-step exploitation_'}

## Escalation Path
{escalation or '_Chain to higher-impact outcome_'}

## Impact
{impact or description}
Severity: {severity}

## Remediation
{remediation_str or '_Concrete fix guidance_'}

## CVSS 4.0
Severity: {severity}
{conf_line}
Vector String (edit via https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator): {cvss_vector}
CWE: {cwe}
OWASP: {owasp}

## Proof / Evidence
{evidence_str}

## References
{references_str}

{f'_Note: {severity_note}_' if severity_note else ''}"""

    if platform == "immunefi":
        return f"""## Bug Description
{description or f'{vuln_type} discovered in {endpoint} on {domain}'}

## Context
{context or '_Protocol component, on-chain or off-chain, who interacts with it._'}

## Impact
{impact or 'Describe the concrete impact on the protocol — funds at risk, governance, asset loss.'}

## Risk Breakdown
Difficulty to Exploit: [Easy/Medium/Hard]
Severity: {severity}
CVSS 4.0: {cvss_vector}

## Proof of Concept Request
{poc_steps or '_Insert HTTP request / transaction_'}

## Steps to Reproduce
{reproduction_str or '1. [Steps needed]'}

## Attack Walkthrough
{walkthrough_str or '_End-to-end exploitation including any required setup_'}

## Escalation
{escalation or '_How this compounds across the protocol_'}

## Recommendation / Remediation
{remediation_str or '_Provide remediation guidance_'}

## References
{references_str}"""

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
