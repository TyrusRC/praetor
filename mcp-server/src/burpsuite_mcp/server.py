"""Burp Suite Swiss Knife MCP Server - Claude Code as pentesting brain."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import (
    read, analyze, send, correlate, collaborate, notes,
    scanner, utility, testing, export, resources, dom, scope, session, payloads, scan, edge,
    intel, cve, report, recon, transform, repeater, macro, scanner_control,
    proxy_control, extract, browser, advisor,
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
Proxy Control: enable/disable intercept, match-and-replace rules, annotations (color+comment), traffic stats, live request polling, traffic pattern monitoring.
Extract: pull specific data from responses — regex, JSON path, CSS selectors, headers, links, hashes. 10x more token-efficient than reading full responses.
Transform: chain encoding operations (url→base64→url), smart auto-decode, encoding detection.
Repeater: two-way Repeater tabs — send, track, iterate, resend with modifications.
Macros: reusable multi-step request sequences with variable extraction across steps.
Scanner Control: pause, resume, cancel scans, poll for new findings in real-time.
Browser: stealth headless Chromium routed through Burp proxy — browse, click, crawl, fill forms. ALL traffic populates proxy history automatically.
Advisor: strategic hunt advisor — get_hunt_plan() returns what to test and in what order. pick_tool() selects the right tool instantly. assess_finding() validates before reporting. Saves 200-500 thinking tokens per decision.

ADVISOR STRATEGY — Token-Efficient Hunting:
Instead of reasoning about what to do next, call the advisor tools:
- get_hunt_plan(target) — FIRST call for any new target. Returns complete phased plan.
- get_next_action() — When unsure what's next. Returns ONE specific tool call.
- pick_tool(task) — When you know WHAT but not WHICH tool. Returns tool + example.
- assess_finding() — BEFORE save_finding(). Validates against 7-Question Gate.
- run_recon_phase(target) — Execute entire recon in ONE call (replaces 5-8 tool calls).

PROXY HISTORY — Browser vs HTTP Client:
browser_crawl/browser_navigate route through Burp PROXY → appears in proxy history.
curl_request/send_http_request use Burp HTTP CLIENT → appears in sitemap only.
Use browser tools first to populate proxy history, then extract_*/annotate_* tools work on those items.

Optimal flow:
1. get_hunt_plan(target) — get strategy (or run_recon_phase for one-call recon)
2. browser_crawl(target) — populate proxy history
3. get_proxy_history() → smart_analyze / extract_* — analyze
4. auto_probe / fuzz / test_* — attack
5. assess_finding() → save_finding() — document

Workflow: Plan → Browse → Analyze → Attack → Verify → Document.""",
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
transform.register(mcp)  # encoding chains, smart decode, encoding detection
repeater.register(mcp)   # tracked Repeater tabs with iterative resend
macro.register(mcp)      # reusable request macros with variable extraction
scanner_control.register(mcp)  # pause, resume, cancel scans + poll new findings
proxy_control.register(mcp)    # intercept, match-replace, annotations, stats, traffic monitoring
extract.register(mcp)          # response extraction: regex, JSON path, CSS selector, headers, links, hash
browser.register(mcp)          # stealth headless browser through Burp proxy — crawl, click, fill forms
advisor.register(mcp)          # strategic hunt advisor — pre-computed plans, tool selection, finding validation
