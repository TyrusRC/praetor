"""Findings hub: remediation lifecycle + multi-scanner import + egress.

Turns Praetor into a consolidation hub — track findings to closure (owner,
SLA, MTTR), ingest external scanner output (Nuclei/Nessus/SARIF/Burp/OpenVAS/
ZAP) under the native dedup key, and push findings out to trackers
(GitHub/GitLab/Jira) and SIEM/webhook collectors. Import/remediation cores are
pure with no network; tracker/egress make operator-owned outbound calls (not
via Burp) using credentials read from environment variables.
"""

from mcp.server.fastmcp import FastMCP

from . import remediation, importer, tracker, egress


def register(mcp: FastMCP) -> None:
    remediation.register(mcp)
    importer.register(mcp)
    tracker.register(mcp)
    egress.register(mcp)
