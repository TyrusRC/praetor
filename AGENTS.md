# Agent Team Configuration

This project uses specialized agents for parallel pentesting. The orchestrator (main conversation) dispatches agents for independent work streams, merges results, and makes strategic decisions.

## Agent Roles

### recon-agent
**Purpose:** Map the target's attack surface in parallel with other analysis.
**When to dispatch:** Start of any new engagement or when endpoints section is stale.
**Tools it should use:** `discover_attack_surface`, `discover_common_files`, `full_recon`, `detect_tech_stack`, `get_unique_endpoints`, `discover_hidden_parameters`
**Returns:** Endpoint list with risk scores, tech stack, sensitive files found, hidden parameters.

### js-analyst
**Purpose:** Deep JavaScript analysis — secrets, DOM sinks, API endpoints.
**When to dispatch:** After recon identifies JS files, or in parallel with recon.
**Tools it should use:** `fetch_page_resources`, `extract_js_secrets`, `analyze_dom`, `extract_api_endpoints`, `fetch_resource`
**Returns:** Found secrets (with severity), DOM XSS sink-to-source flows, hidden API endpoints.

### vuln-scanner
**Purpose:** Test a specific vulnerability category on assigned endpoints.
**When to dispatch:** After recon, one agent per vuln category on non-overlapping targets.
**Tools it should use:** `auto_probe`, `bulk_test`, `probe_endpoint`, `fuzz_parameter`, `test_lfi`, `test_file_upload`, `test_cors`, `test_graphql`, `test_cloud_metadata`, `test_open_redirect`, `test_jwt`, `get_payloads`
**Returns:** Findings with scores, tested parameters, anomalies for investigation.
**Important:** Each vuln-scanner agent gets a DIFFERENT set of targets or categories to avoid duplicate requests.

### finding-verifier
**Purpose:** Re-verify confirmed findings and investigate anomalies.
**When to dispatch:** On session resume with stale findings, or after scanning finds anomalies.
**Tools it should use:** `session_request`, `compare_auth_states`, `auto_collaborator_test`, `get_collaborator_interactions`, `compare_responses`, `save_target_intel`
**Returns:** Updated finding status (confirmed/stale/likely_false_positive) with evidence.

### payload-crafter
**Purpose:** Craft bypass payloads when standard attacks are blocked by WAF/filters.
**When to dispatch:** When vuln-scanner reports all payloads blocked on a parameter that looks injectable.
**Tools it should use:** `fuzz_parameter`, `get_payloads`, `decode_encode`, `session_request`, `probe_endpoint`, `save_target_notes`
**Returns:** Working bypass payload with filter map, or "filter too strong" with evidence.

### auth-tester
**Purpose:** Test authorization and access control across endpoints.
**When to dispatch:** When multiple sessions/auth states are available (admin + user + anon).
**Tools it should use:** `test_auth_matrix`, `compare_auth_states`, `test_race_condition`, `test_parameter_pollution`, `test_jwt`, `session_request`
**Returns:** IDOR findings, auth bypass results, race condition results.

### browser-agent
**Purpose:** Browser-based crawling and JavaScript interaction for SPA/JS-heavy targets.
**When to dispatch:** When target has extensive client-side rendering, Angular/React/Vue apps, or auto-loading content that server-side crawling misses.
**Tools it should use:** `browser_navigate`, `browser_crawl`, `browser_interact_all`, `browser_click`, `browser_fill`, `browser_execute_js`, `browser_get_page_info`, `browser_get_links`
**Returns:** Discovered endpoints from JS rendering, dynamic routes, XHR/API calls captured in proxy history.
**Constraint:** Only ONE browser agent at a time — single browser instance.

## Dispatch Rules

1. **Never dispatch agents that make requests to the SAME endpoint simultaneously** — this can trigger WAF rate limiting and corrupt results.
2. **All agents must use the SAME session** for authentication consistency (sessions are thread-safe in the Java extension).
3. **The orchestrator does NOT duplicate work** — if you dispatch an agent to scan for SQLi, don't also scan for SQLi yourself.
4. **Merge results before next strategic decision** — wait for all parallel agents to complete before deciding what to investigate next.
5. **Save intel after merging** — the orchestrator calls `save_target_intel` with merged results, not individual agents.
6. **Browser agents cannot run in parallel** — only one headless browser instance exists.
7. **Use browser_crawl before extraction tools** — proxy history must be populated first.

## Parallelization Patterns

### Pattern 1: Recon Fanout
Dispatch simultaneously at the start of an engagement:
- recon-agent: crawl and map endpoints
- js-analyst: scan JS files for secrets and DOM XSS
Both run in background. Orchestrator merges results into attack priority list.

### Pattern 2: Vulnerability Parallel
After recon, split targets by vulnerability category:
- vuln-scanner (SQLi): endpoints with id/num/page params
- vuln-scanner (XSS): endpoints with search/comment/name params
- vuln-scanner (LFI): endpoints with file/path/include params
- auth-tester: all authenticated endpoints (IDOR matrix)
Each agent gets non-overlapping targets.

### Pattern 3: Verify Batch
On session resume, verify multiple findings simultaneously:
- finding-verifier #1: re-verify CRITICAL findings
- finding-verifier #2: re-verify HIGH findings
- finding-verifier #3: re-verify MEDIUM findings

### Pattern 4: Investigation + Continued Scanning
When an anomaly is found:
- payload-crafter: investigate the anomaly (foreground, need results)
- vuln-scanner: continue testing next category (background)

## Anti-Patterns

- **Don't dispatch agents for trivial work** — a single `quick_scan` call doesn't need an agent
- **Don't dispatch more than 4 agents simultaneously** — MCP server handles requests sequentially, too many agents create a queue
- **Don't let agents make strategic decisions** — agents execute, the orchestrator decides
- **Don't skip the merge step** — always collect and analyze all agent results before proceeding
- **Don't dispatch agents for sequential workflows** — login flows, CSRF extraction chains, and run_flow steps must be sequential
