"""build_finding_section — one finding to professional-standard markdown."""

from praetor.tools._framework_map import framework_tags

from ._evidence_fmt import _is_internal_evidence, format_poc_request, format_repro_steps

def build_finding_section(finding: dict, index: int, internal: bool = False) -> str:
    """Build a single finding section to professional pentest standard.

    Args:
        internal: True renders operator bookkeeping (Burp indices, workspace
            paths, replay tables). False — the default, and what a client or
            triager receives — omits them: they are unresolvable outside this
            Burp session and read as tool output, not evidence.
    """
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
    cvss = finding.get("cvss4_vector") or finding.get("cvss_vector") or finding.get("cvss", "")
    cvss_band = finding.get("cvss4_severity", "")
    vuln_type = finding.get("vulnerability_type") or finding.get("vuln_type", "")

    # Framework tagging (W34-b): MITRE ATT&CK / WSTG / OWASP / CWE from the
    # class lookup. Finding-supplied cwe/owasp always win; map fills the gap.
    fw = framework_tags(finding.get("vuln_type") or vuln_type)
    if not cwe:
        cwe = fw.get("cwe", "")
    if not owasp:
        owasp = fw.get("owasp", "")

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
    if fw.get("attack_ck"):
        name = fw.get("attack_name", "")
        ids = ", ".join(fw["attack_ck"])
        lines.append(f"- MITRE ATT&CK: {ids}" + (f" ({name})" if name else ""))
    if fw.get("wstg"):
        lines.append(f"- OWASP WSTG: {fw['wstg']}")
    if cvss:
        lines.append(f"- CVSS 4.0 vector: `{cvss}`")
    lines.append(f"- Severity: **{severity}**")
    # A label that disagrees with its own vector is the thing a reader spots
    # first. Surface it to the operator rather than shipping it silently.
    if internal and cvss_band and cvss_band.upper() != str(severity).upper():
        lines.append(
            f"- _Operator note: vector scores {cvss_band}; reconcile before delivery._"
        )
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

    evidence_rows: list[tuple[str, object]] = []
    if isinstance(evidence, dict):
        evidence_rows = [
            (k, v) for k, v in evidence.items()
            if internal or not _is_internal_evidence(k, v)
        ]

    has_evidence_body = bool(
        evidence_rows
        or (isinstance(evidence, str) and evidence.strip())
        or (evidence_text and evidence_text.strip())
        or (reproductions and internal)
    )
    if has_evidence_body:
        lines.append("**Evidence**")
        for k, v in evidence_rows:
            lines.append(f"- {k}: `{str(v)[:200]}`")
        if isinstance(evidence, str) and evidence.strip():
            lines.append(f"```\n{evidence[:800]}\n```")
        # Replay tables prove reproducibility to the operator, not to the
        # reader — Rule 16a keeps activity counts out of the deliverable.
        if reproductions and internal:
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
        elif reproductions and not internal:
            # Rule 16a: no counts in the deliverable — the qualitative claim is
            # what the reader needs; the tally stays in evidence.reproductions[].
            lines.append("")
            lines.append("Behaviour reproduced consistently on independent replays.")
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

    # ── Detection guidance (blue-team / purple-team pairing, W34-b)
    detection = fw.get("detection") or {}
    if any(detection.get(k) for k in ("sigma", "spl", "kql")):
        lines.append("**Detection Guidance (Blue Team)**")
        lines.append(
            "Paired defensive rules — how a defender would spot this attack class "
            "in web, proxy, or WAF telemetry:"
        )
        lines.append("")
        if detection.get("sigma"):
            lines.append("- Sigma:")
            lines.append(f"  ```\n  {detection['sigma']}\n  ```")
        if detection.get("spl"):
            lines.append("- Splunk (SPL):")
            lines.append(f"  ```\n  {detection['spl']}\n  ```")
        if detection.get("kql"):
            lines.append("- Microsoft Sentinel (KQL):")
            lines.append(f"  ```\n  {detection['kql']}\n  ```")
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
