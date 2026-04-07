"""Burp Suite Swiss Knife MCP Server - Claude Code as pentesting brain."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import (
    read, analyze, send, correlate, collaborate, notes,
    scanner, utility, testing, export, resources, dom, scope, session, payloads, scan, edge,
    intel, cve, report, recon,
)

mcp = FastMCP(
    "burpsuite-swiss-knife",
    instructions="""You are connected to Burp Suite via the Swiss Knife MCP server.

Read: proxy history, scanner findings, sitemap, scope, cookies, WebSocket messages.
Analyze: parameters, forms, endpoints, injection points, tech stack, JS secrets (TruffleHog/Gitleaks-quality), DOM structure, JS sinks/sources.
Send: HTTP requests like curl/httpx with auth, redirects, cookies. Send to Repeater/Intruder.
Scan: trigger active scans, crawls, check status (requires Burp Professional).
Fuzz: smart fuzzing with Claude-generated payloads, attack types (sniper/battering ram/pitchfork/cluster bomb), anomaly detection.
Compare: enhanced response diff, send to Burp's Comparer, auth state comparison for IDOR.
Collaborate: Burp Collaborator payloads, auto-test (inject+send+poll for blind vulns).
Export: sitemap as compact JSON or OpenAPI 3.0, fetch static resources (JS/CSS/source maps).
Utility: encode/decode (base64, URL, HTML, hex, JWT, hashes).
Notes: save findings, export pentest reports.
Intel: persistent target memory across sessions, staleness detection, finding verification states, cross-target pattern learning.
CVE: match tech stack against known vulnerabilities, generate search URLs.
Report: professional pentest reports with executive summary, platform-specific formatting (HackerOne, Bugcrowd, Intigriti, Immunefi).
Recon: external tool orchestration (subfinder, httpx, nuclei) — graceful degradation if tools missing.

Workflow: Read → Analyze attack surface → Fuzz/Test → Correlate → Document.""",
)

# Register all tool modules
read.register(mcp)        # proxy history, sitemap, scope, cookies, websocket
analyze.register(mcp)     # parameters, forms, endpoints, injection points, tech stack, js secrets, dom
send.register(mcp)        # HTTP send, raw, resend, repeater, intruder, curl
correlate.register(mcp)   # search, findings correlation, response diff
collaborate.register(mcp) # collaborator payloads, interactions, auto-test
notes.register(mcp)       # save/get/export findings
scanner.register(mcp)     # scan URL, crawl target, scan status
utility.register(mcp)     # encode/decode (base64, URL, HTML, hex, JWT, hashes)
testing.register(mcp)     # fuzz, compare auth, comparer, enhanced diff
export.register(mcp)      # sitemap export (JSON + OpenAPI)
resources.register(mcp)   # static resources (JS/CSS/source maps)
dom.register(mcp)         # DOM structure + JS sink/source analysis
scope.register(mcp)       # smart scope configuration with auto-filtering
session.register(mcp)    # persistent attack sessions, cookie jar, multi-step flows
payloads.register(mcp)  # context-aware payload lookup from curated knowledge base
scan.register(mcp)      # adaptive scan: discover attack surface + auto-probe with knowledge base
edge.register(mcp)      # edge-case testing: JWT, CORS, GraphQL, cloud metadata, common files
intel.register(mcp)     # persistent target intelligence storage across sessions
cve.register(mcp)      # CVE intelligence: match tech stack against known vulnerabilities
report.register(mcp)   # professional pentest report generation with platform templates
recon.register(mcp)    # external recon tool orchestration (subfinder, httpx, nuclei)
