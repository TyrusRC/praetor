"""Static-analysis layer: opengrep over crawled proxy artifacts.

Tools:
    audit_crawled_artifacts — opengrep against JS/HTML bodies captured in
        Burp proxy history. Identifies DOM-XSS sinks, prototype-pollution
        merges, postMessage handlers without origin checks, exposed secrets.
        Static counterpart to analyze_dom (which is dynamic).

Source-tree SAST moved to the mantis engine — see run_mantis (tools/mantis_audit.py).
"""

from mcp.server.fastmcp import FastMCP

from . import opengrep_audit


def register(mcp: FastMCP) -> None:
    opengrep_audit.register(mcp)
