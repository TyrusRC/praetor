"""Findings hub: remediation lifecycle + multi-scanner import/dedup.

Turns Praetor into a consolidation hub — track findings to closure (owner,
SLA, MTTR) and ingest external scanner output (Nuclei/Nessus) under the
native dedup key. Pure-function cores; no Burp client, no network.
"""

from mcp.server.fastmcp import FastMCP

from . import remediation, importer


def register(mcp: FastMCP) -> None:
    remediation.register(mcp)
    importer.register(mcp)
