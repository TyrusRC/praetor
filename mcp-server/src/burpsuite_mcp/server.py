"""Burp Suite Swiss Knife MCP Server - Claude Code as pentesting brain."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools import (
    read, analyze, send, correlate, collaborate, notes,
    scanner, utility, testing, export, resources, dom, scope, session, payloads, scan, edge,
    intel, cve, report, recon, recon_extended, transform, repeater, macro, scanner_control,
    proxy_control, extract, browser, advisor, testing_extended, burp_tools, dom_probe,
    prompts, resources_mcp, mutate, exploit, auth, vuln, research, harvest, dom_xss_executed,
    bucket_urls, scope_extra, wordlist, secrets, analysis, security,
    shadow_repeater, easm, recon_pd, waf_bypass,
    sca, llm_redteam, k8s_audit, smuggle_cli, vulnwalker, httpql,
    cloud_audit, iac_scan, ci_audit, visual_easm,
    source_aware, benchmark, mobile_payloads, cua_probe, sast_handoff, pyexploit,
    http3_probe, local_llm, mcptox,
    web_llm_sweep, grpc_probe, saml_xsw_probe, dns_rebind_probe,
    postmessage_probe, csp_analyzer, sse_probe, nuclei_llm_infra,
    auth_negotiate, mcp_jsonrpc_probe,
    cve_variant_probe,
    smart_js_analyze,
    smart_request_triage,
    extract_batch,
)

mcp = FastMCP(
    "burpsuite-swiss-knife",
    instructions="""You are connected to Burp Suite via the Swiss Knife MCP server.

Read: proxy history, scanner findings, sitemap, scope, cookies, WebSocket messages.
Analyze: parameters, forms, endpoints, injection points, tech stack, JS secrets (TruffleHog/Gitleaks-quality), DOM structure, JS sinks/sources.
Send: HTTP requests like curl with auth, redirects, cookies. Send to Repeater/Intruder.
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
Recon: external tool orchestration (subfinder, nuclei, katana) — graceful degradation if tools missing.
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
scope_extra.register(mcp)   # import_scope: bulk scope import from recon output
wordlist.register(mcp)      # generate_smart_wordlist: tech-aware SecLists slicer + recon priors
session.register(mcp)    # persistent attack sessions, cookie jar, multi-step flows
payloads.register(mcp)  # context-aware payload lookup from curated knowledge base
scan.register(mcp)      # adaptive scan: discover attack surface + auto-probe with knowledge base
edge.register(mcp)      # edge-case testing: JWT, CORS, GraphQL, cloud metadata, common files
intel.register(mcp)     # persistent target intelligence storage across sessions
cve.register(mcp)      # CVE intelligence: match tech stack against known vulnerabilities
report.register(mcp)   # professional pentest report generation with platform templates
recon.register(mcp)    # external recon tool orchestration (subfinder, nuclei, katana)
recon_extended.register(mcp)  # Python-only recon: crt.sh, wayback, DNS, takeover, rate limit
transform.register(mcp)  # encoding chains, smart decode, encoding detection
repeater.register(mcp)   # tracked Repeater tabs with iterative resend
macro.register(mcp)      # reusable request macros with variable extraction
scanner_control.register(mcp)  # pause, resume, cancel scans + poll new findings
proxy_control.register(mcp)    # intercept, match-replace, annotations, stats, traffic monitoring
extract.register(mcp)          # response extraction: regex, JSON path, CSS selector, headers, links, hash
browser.register(mcp)          # stealth headless browser through Burp proxy — crawl, click, fill forms
advisor.register(mcp)          # strategic hunt advisor — pre-computed plans, tool selection, finding validation
testing_extended.register(mcp)  # advanced testing: API schema, GraphQL deep, business logic, smuggling, cache poisoning
burp_tools.register(mcp)       # Burp native: WebSocket send, Organizer, Decoder, Logger, Project info, Intruder config
dom_probe.register(mcp)        # DOM-aware probe — closes the client-side gap (DOM XSS, DOM-redirect, CSPP, link-manip, DOM-data-manip)
prompts.register(mcp)          # MCP Prompts — operator-invokable workflow templates (hunt-target, verify-finding, chain-findings, save-finding-checklist, triage-program)
resources_mcp.register(mcp)    # MCP Resources — read-only context (rules, skills, knowledge, intel, findings) under burp:// URIs
mutate.register(mcp)           # mutate_payload — bypass-variant generator (encoding/case/comment/null/whitespace/quote rotation/length-pad)
secrets.register(mcp)          # gitleaks / trufflehog / git-dumper wrappers — secret leakage + .git exposure chain
analysis.register(mcp)         # opengrep static audit — audit_crawled_artifacts (proxy bodies) + run_opengrep_source (repo SAST)
security.register(mcp)         # prompt-injection guardrail + destructive-command tripwire (operator-policy)
exploit.register(mcp)          # confirm_* tools — exploit-to-confirm with tool-layer destructive denylist (rm/DROP/useradd hard-refused; reverse shells / LOLBAS SOC-loud warn-and-allow)
auth.register(mcp)             # advanced auth attacks — forge_jwt / crack_jwt_secret (native, no jwt_tool dep) / test_session_lifecycle / test_login_bypass / test_mfa_bypass / analyze_reset_tokens
vuln.register(mcp)             # vuln-class orchestrators where no third-party covers the surface — test_csrf / test_ssrf / test_ssti / test_xxe / test_websocket / test_prototype_pollution
research.register(mcp)         # research_attack_vector — curated bundle of deep-dive prompts + disclosed-report URLs + writeup-hub searches + chain hypotheses for any vuln class (no internet call from server; Claude WebFetches the curated URLs)
harvest.register(mcp)          # harvest_identifiers — pull IDs/emails/UUIDs/ULIDs/Snowflakes/JWTs out of captured traffic for IDOR pivots (Strix-derived; complements extract_js_secrets which is single-index, API-key focused)
dom_xss_executed.register(mcp) # probe_xss_executed — headless dialog-hook XSS execution proof (nuclei-DAST pattern); promotes findings from "reflected" to "EXECUTED"
bucket_urls.register(mcp)      # bucket_urls_by_vuln_class — gf-pattern URL classifier feeding targeted auto_probe (reconftw-derived; 5-10× more token-efficient than spray-fuzz)
shadow_repeater.register(mcp)  # shadow_repeater — silent mutation pass on a captured request; reports anomalies vs baseline
easm.register(mcp)             # recorded_login + findings_diff + format_pr_comment + easm_monitor_loop
recon_pd.register(mcp)         # PD suite: dnsx/naabu/tlsx/asnmap/uncover/cloudlist/notify/mapcves/cdncheck/alterx + graphw00f
waf_bypass.register(mcp)       # probe_40x_bypass (in-process header/path/method tricks) + dontgo403 + byp4xx wrappers
sca.register(mcp)              # osv-scanner / trivy / grype — SCA + container + IaC
llm_redteam.register(mcp)      # garak / pyrit / mcp-scan — LLM endpoint + MCP server attack surface
k8s_audit.register(mcp)        # kubescape / kube-hunter — posture + active K8s recon
smuggle_cli.register(mcp)      # smuggle CLI — Kettle 2025 0.CL/CL.0/V-H/Expect/RQP/double-desync detector
vulnwalker.register(mcp)       # vulnwalker_audit — AST call-chain walker (Python) with taint-source matching
httpql.register(mcp)           # query_history_dsl — small HTTPQL-style DSL over Burp proxy history
cloud_audit.register(mcp)      # prowler / scout_suite / cloudsploit — multi-cloud config posture
iac_scan.register(mcp)         # checkov / tfsec / terrascan / hadolint — IaC + Dockerfile policy
ci_audit.register(mcp)         # poutine / octoscan — GitHub Actions / GitLab CI injection + pwn-request
visual_easm.register(mcp)      # visual_easm_diff — gowitness screenshot + hash delta vs prior run
source_aware.register(mcp)     # xvulnhuntr / vulnhuntr — LLM-chain SAST input→sink (white-box mode)
benchmark.register(mcp)        # run_autopenbench / run_caibench — publishable AI-pentest benchmarks (W7)
mobile_payloads.register(mcp)  # mobile_frida_snippet / mobile_adb_pack — payload delivery for mobile-mastg (W8)
cua_probe.register(mcp)        # probe_cua_injection_surface — detects CUA-hijack vectors (W22-b)
sast_handoff.register(mcp)     # sast_to_endpoint_risk / risk_rank_endpoints — SAST → DAST handoff (W22-e)
pyexploit.register(mcp)        # run_pyexploit — Python exploit-dev sandbox (W23-a / Strix-parity)
http3_probe.register(mcp)      # probe_http3_downgrade — HTTP/3 reachability + H2/H3 fingerprint differential (W27-a)
local_llm.register(mcp)        # probe_local_llm + run_local_llm_prompt_injection — Ollama / LM Studio / llama.cpp routing (W27-b)
mcptox.register(mcp)           # run_mcptox — MCP-server self-audit (W27-c, heuristic + license-gated corpus)
web_llm_sweep.register(mcp)    # discover_llm_endpoint + run_web_llm_owasp_top10 — Invicti BLOCKER closure (W29-a)
grpc_probe.register(mcp)       # probe_grpc_reflection + probe_grpc_idor — gRPC active surface (W29-b)
saml_xsw_probe.register(mcp)   # probe_saml_xsw — SAML XSW + sig-exclusion + comment-injection (W29-c)
dns_rebind_probe.register(mcp) # probe_dns_rebind — rbndr.us TOCTOU SSRF (W29-d)
postmessage_probe.register(mcp)  # probe_postmessage_listeners — browser-driven origin-policy fuzz (W29-e)
csp_analyzer.register(mcp)     # analyze_csp — Content-Security-Policy bypass analyzer (W29-f)
sse_probe.register(mcp)        # probe_sse_injection — SSE newline injection (W29-g)
nuclei_llm_infra.register(mcp) # run_nuclei_llm_infra — LLM/AI/MCP template sweep (W29-h)
auth_negotiate.register(mcp)   # probe_kerberos_spnego_auth — enterprise auth gateway detection (W29-j)
mcp_jsonrpc_probe.register(mcp)  # probe_mcp_jsonrpc_methods — Wallarm ultimate-detect parity (W29-k)
cve_variant_probe.register(mcp)  # probe_cve_with_variants — bounded CVE-aware PoC sweep (W30-a)
smart_js_analyze.register(mcp)   # smart_js_analyze — JS → fire-ready attack plan (W30-b)
smart_request_triage.register(mcp)  # smart_request_triage — proxy entry → attack plan (W30-c)
extract_batch.register(mcp)         # extract_js_secrets_batch / extract_api_endpoints_batch / extract_links_batch — dedup across N indices in one call (W31-b)
