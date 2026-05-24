"""Static-analysis layer (Praetor v1.0): opengrep over crawled artifacts + source.

Tools:
    audit_crawled_artifacts — opengrep against JS/HTML bodies captured in
        Burp proxy history. Identifies DOM-XSS sinks, prototype-pollution
        merges, postMessage handlers without origin checks, exposed secrets.
        Static counterpart to analyze_dom (which is dynamic).
    run_opengrep_source     — opengrep against a source-code tree for SAST.
        Same engine, source-tree input. Closes the SAST gap without making
        Praetor a code analyzer.
"""

from mcp.server.fastmcp import FastMCP

from . import opengrep_audit, opengrep_source


def register(mcp: FastMCP) -> None:
    opengrep_audit.register(mcp)
    opengrep_source.register(mcp)
