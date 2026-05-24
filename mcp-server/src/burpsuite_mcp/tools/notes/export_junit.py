"""JUnit XML exporter — let CI runners surface DAST findings as failed tests.

GitHub Actions, GitLab CI, Jenkins, CircleCI all parse JUnit XML for the
per-job test report tab. Each saved finding becomes one <testcase>; severity
maps to PASS / FAILURE / ERROR so a CRITICAL finding breaks the build.

Schema: Apache Ant JUnit XML — the de-facto contract every CI tool consumes.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_FAILING_SEVERITIES = {"CRITICAL", "HIGH"}
_WARNING_SEVERITIES = {"MEDIUM"}


def _to_junit(findings: list[dict], suite_name: str = "praetor.dast") -> str:
    failures = sum(
        1 for f in findings if str(f.get("severity") or "").upper() in _FAILING_SEVERITIES
    )
    errors = sum(
        1 for f in findings if str(f.get("severity") or "").upper() == "CRITICAL"
    )

    out: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<testsuite name="{escape(suite_name)}" tests="{len(findings)}" '
            f'failures="{failures}" errors="{errors}" skipped="0">'
        ),
    ]

    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        vuln = (f.get("vuln_type") or "unknown").lower()
        endpoint = f.get("endpoint") or ""
        title = f.get("title") or vuln.upper()
        desc = f.get("description") or ""
        evidence_text = f.get("evidence_text") or ""

        case_name = f"{vuln} @ {endpoint[:80]}".strip()
        classname = f"praetor.{vuln}"

        out.append(
            f'  <testcase classname="{escape(classname)}" name="{escape(case_name)}" time="0">'
        )

        message = f"[{sev}] {title}"
        payload = f"{desc}\n\nEvidence: {evidence_text}".strip()
        if sev == "CRITICAL":
            out.append(
                f'    <error message="{escape(message)}" type="{escape(vuln)}"><![CDATA[{payload}]]></error>'
            )
        elif sev in _FAILING_SEVERITIES:
            out.append(
                f'    <failure message="{escape(message)}" type="{escape(vuln)}"><![CDATA[{payload}]]></failure>'
            )
        elif sev in _WARNING_SEVERITIES:
            out.append(f'    <system-out><![CDATA[[MEDIUM] {payload}]]></system-out>')
        else:
            out.append(f'    <system-out><![CDATA[[{sev}] {payload}]]></system-out>')

        out.append("  </testcase>")

    out.append("</testsuite>")
    return "\n".join(out)


def register(mcp: FastMCP):

    @mcp.tool()
    async def export_junit(
        endpoint: str = "",
        suite_name: str = "praetor.dast",
        confirmed_only: bool = True,
    ) -> str:
        """Export saved findings as JUnit XML (CI test-report compatible).

        CRITICAL findings emit <error>; HIGH emit <failure> (breaks build by default);
        MEDIUM/LOW/INFO emit <system-out> (warning-only).

        Args:
            endpoint: Optional URL substring filter
            suite_name: <testsuite name=...> attribute
            confirmed_only: If True, exclude suspected / likely_false_positive / stale
        """
        params: dict[str, str] = {}
        if endpoint:
            params["endpoint"] = endpoint
        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        findings = data.get("findings", []) or []
        if confirmed_only:
            findings = [f for f in findings if str(f.get("status") or "").lower() == "confirmed"]

        return _to_junit(findings, suite_name=suite_name)
