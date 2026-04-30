"""Professional pentest report generation.

Submodules:
  - lifecycle  : load_intel, purge_false_positives, status sets
  - severity   : honest_severity, cvss_v4_vector, severity_sort_key
  - builders   : executive summary, finding section, methodology, coverage
  - platforms  : HackerOne / Bugcrowd / Intigriti / Immunefi templates
"""

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.report.builders import (
    build_coverage_section,
    build_executive_summary,
    build_finding_section,
    build_methodology_section,
)
from burpsuite_mcp.tools.report.lifecycle import (
    HARD_DELETE_STATUSES,
    REPORTABLE_STATUSES,
    load_intel,
    purge_false_positives,
)
from burpsuite_mcp.tools.report.platforms import format_platform_finding
from burpsuite_mcp.tools.report.severity import severity_sort_key


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_report(
        domain: str,
        format: str = "pentest",
        platform: str = "",
        include_coverage: bool = True,
        include_suspected: bool = False,
    ) -> str:
        """Generate a professional pentest report from saved findings. True-positives only; hard-deletes false positives.

        Args:
            domain: Target domain
            format: 'pentest', 'executive', or 'findings'
            platform: '' or 'hackerone', 'bugcrowd', 'intigriti', 'immunefi'
            include_coverage: Include test-coverage section (default True)
            include_suspected: Include suspected/stale findings (default False)
        """
        # 1) Hard-delete false positives BEFORE loading.
        _kept, deleted_count = purge_false_positives(domain)

        findings_data = load_intel(domain, "findings")
        profile = load_intel(domain, "profile")
        coverage = load_intel(domain, "coverage") if include_coverage else {}

        findings = findings_data.get("findings", [])

        # Merge Burp's in-memory findings, applying same FP filter.
        burp_data = await client.get("/api/notes/findings")
        if "error" not in burp_data:
            for jf in burp_data.get("findings", []):
                if jf.get("status") in HARD_DELETE_STATUSES:
                    continue
                if not any(
                    f.get("endpoint") == jf.get("endpoint") and
                    (f.get("title") == jf.get("title") or f.get("vulnerability_type") == jf.get("title"))
                    for f in findings
                ):
                    findings.append(jf)

        # 2) True-positives-only gate.
        total_before_filter = len(findings)
        if not include_suspected:
            findings = [f for f in findings if f.get("status") in REPORTABLE_STATUSES]
        excluded_non_confirmed = total_before_filter - len(findings)

        if not findings:
            msg_parts = [f"No reportable (status='confirmed') findings for {domain}."]
            if deleted_count:
                msg_parts.append(f"Hard-deleted {deleted_count} likely_false_positive entries.")
            if excluded_non_confirmed:
                msg_parts.append(
                    f"Excluded {excluded_non_confirmed} suspected/stale findings — "
                    "verify them via the verify-finding skill, or pass include_suspected=True for a draft."
                )
            return " ".join(msg_parts)

        findings.sort(key=lambda f: severity_sort_key(f.get("severity", "INFO")))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Single-finding platform shortcut.
        if platform and len(findings) == 1:
            return format_platform_finding(findings[0], platform, domain)

        # Full report assembly.
        sections = []
        if format in ("pentest", "executive"):
            sections.append(f"# Security Assessment Report: {domain}")
            sections.append(f"**Date:** {now}")
            if deleted_count:
                sections.append(f"_Pre-flight: hard-deleted {deleted_count} likely_false_positive findings._")
            if excluded_non_confirmed and not include_suspected:
                sections.append(
                    f"_Excluded {excluded_non_confirmed} suspected/stale findings (true-positives-only gate)._"
                )
            sections.append("")
            sections.append(build_executive_summary(findings, domain, profile))

        if format == "executive":
            return "\n".join(sections)

        if format == "pentest":
            sections.append("")
            sections.append(build_methodology_section())

        sections.append("")
        sections.append("## Findings")
        sections.append("")
        for i, finding in enumerate(findings, 1):
            sections.append(build_finding_section(finding, i))

        if include_coverage and coverage:
            sections.append(build_coverage_section(coverage))

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
        """Format a specific saved finding for a bug-bounty platform.

        Args:
            domain: Target domain
            finding_id: Finding ID (e.g. 'f001') from save_target_intel
            platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'immunefi'
        """
        findings_data = load_intel(domain, "findings")
        findings = findings_data.get("findings", [])

        for f in findings:
            if f.get("id") == finding_id:
                return format_platform_finding(f, platform, domain)

        return f"Finding {finding_id} not found for {domain}. Available: {[f.get('id') for f in findings[:10]]}"
