---
name: dispatch-agents
description: Orchestrate parallel pentesting agents — dispatch specialists for recon, scanning, verification, and payload crafting simultaneously
---

# Dispatch Parallel Agents

You are the orchestrator. Your job is to identify independent work streams and dispatch specialized agents to run in parallel, dramatically reducing total testing time. A full hunt that takes 50 sequential tool calls can finish in 15 with proper parallelism.

**Concurrency cap: up to 6 simultaneous agents.** The Java extension's HTTP server uses a fixed thread pool of 6 (see `ApiServer.java`), so 6 in-flight MCP requests run truly in parallel. Beyond 6, requests queue. Earlier guidance capped this at 3-4 — that was wrong; correct it whenever you see it.

## Mandatory Briefing Block

Every dispatched subagent MUST receive these three lines verbatim in addition to its task. Subagents do not see prior conversation, so without this block they hallucinate file paths, line numbers, function names, and findings — observed multiple times in past audits.

```
VERIFY before reporting: every file:line you cite must be opened and read in this run; every symbol you name must be grepped in this run; every finding you claim must reference an existing logger_index from get_proxy_history or get_logger_entries. If you cannot verify a claim, mark it UNVERIFIED rather than reporting it as fact.

EVIDENCE FORMAT: report findings as `<severity> | <file>:<line> | <one-line problem> | <one-line fix>`. No prose, no speculation, no recommendations beyond the fix line.

SCOPE GUARD: do not act outside your assigned scope. Recon agents do not test vulnerabilities. Vuln-scanner agents do not exfiltrate data. Verifier agents do not save findings (they report back; orchestrator persists).
```

When you write the dispatch prompt, paste the block above ahead of the task-specific instructions. No shortcuts.

## When to Use This Skill

- Starting a new engagement (recon can be parallelized)
- Phase 3 of hunt (vuln testing across multiple categories)
- Resuming a session (multiple findings to re-verify)
- Investigating an anomaly while continuing scanning
- Any time you have 2+ independent tasks that don't share state

## When NOT to Parallelize

- Login/auth flows (must be sequential — cookies depend on previous step)
- `run_flow` multi-step attacks (sequential by design)
- Race condition testing (requires coordinated timing)
- When targets overlap (two agents hitting the same endpoint = rate limit triggers)

## Dispatch Pattern 1: Recon Fanout

At the start of an engagement, dispatch two agents simultaneously:

```
Launch Agent 1 (recon-agent, background):
  "You are a reconnaissance agent for {domain}. Session name: {session}.
  
  1. Run discover_attack_surface(session='{session}', max_pages=20)
  2. Run discover_common_files(session='{session}')
  3. Run discover_hidden_parameters(session='{session}', path='/', wordlist='extended')
  
  Return: complete endpoint list with risk scores, sensitive files found, hidden params.
  Do NOT test for vulnerabilities — only map the surface."

Launch Agent 2 (js-analyst, background):
  "You are a JavaScript analysis agent for {domain}. Session name: {session}.
  
  1. Run quick_scan(session='{session}', method='GET', path='/') to get the root page index
  2. Run fetch_page_resources(index=ROOT_INDEX) to grab all JS files
  3. For each JS file (up to 10): run extract_js_secrets(index=JS_INDEX)
  4. Run analyze_dom(index=ROOT_INDEX) for DOM sink/source analysis
  
  Return: all secrets found (with severity), DOM XSS flows, hidden API endpoints in JS.
  Do NOT test for vulnerabilities — only analyze."
```

**After both complete:** Merge results. The recon agent gives you endpoints + risk scores. The JS analyst gives you secrets + DOM XSS leads. Combine into a prioritized attack plan.

## Dispatch Pattern 2: Parallel Vulnerability Testing

After recon, split targets by category. **Critical rule: no target overlap between agents.**

```
# First, divide targets by parameter risk classification
sqli_targets = [endpoints with id/uid/num/page params]
xss_targets = [endpoints with search/q/comment/name params]
lfi_targets = [endpoints with file/path/include/template params]
auth_endpoints = [all authenticated endpoints for IDOR testing]

Launch Agent 1 (vuln-scanner, background):
  "You are a SQL injection scanner for {domain}. Session: {session}.
  
  Test these specific targets for SQLi ONLY:
  {sqli_targets_json}
  
  Use: auto_probe(session='{session}', targets=TARGETS, categories=['sqli'])
  
  For any finding with score >= 30: re-send the payload once to confirm.
  
  Return: list of findings with scores, tested params count, confirmed vs suspected."

Launch Agent 2 (vuln-scanner, background):
  "You are an XSS scanner for {domain}. Session: {session}.
  
  Test these specific targets for XSS ONLY:
  {xss_targets_json}
  
  Use: auto_probe(session='{session}', targets=TARGETS, categories=['xss'])
  
  For any reflected payload: check if it's in an executable context (not encoded).
  
  Return: list of findings with reflection context, tested params count."

Launch Agent 3 (vuln-scanner, background):
  "You are an LFI/path traversal scanner for {domain}. Session: {session}.
  
  Test these specific targets:
  {lfi_targets_json}
  
  For each target: run test_lfi(session='{session}', path=PATH, parameter=PARAM)
  
  Return: list of findings with file content indicators, tested params count."

Launch Agent 4 (auth-tester, background):
  "You are an authorization tester for {domain}. Sessions: admin={admin_session}, user={user_session}.
  
  Test these endpoints for IDOR:
  {auth_endpoints_json}
  
  Use: test_auth_matrix(endpoints=ENDPOINTS, auth_states={
    'admin': {'session': '{admin_session}'},
    'user': {'session': '{user_session}'},
    'anon': {'remove_auth': true}
  })
  
  Return: IDOR findings with similarity scores, potential access control issues."
```

**After all complete:** Merge all findings. Prioritize by severity. Investigate high-score anomalies.

## Dispatch Pattern 3: Verify Batch

On session resume with multiple stale findings:

```
# Group findings by severity
critical_findings = [findings where severity == 'CRITICAL']
high_findings = [findings where severity == 'HIGH']
other_findings = [findings where severity in ('MEDIUM', 'LOW')]

Launch Agent 1 (finding-verifier, foreground — need results immediately):
  "You are verifying CRITICAL findings for {domain}. Session: {session}.
  
  For each finding, re-send the exact poc_request and check:
  {critical_findings_json}
  
  Evidence requirements:
  - SQLi: timing > 3x baseline (test 3 times)
  - XSS: payload unencoded in response
  - SSRF: Collaborator interaction
  - RCE: command output in response
  
  Return: updated status (confirmed/stale/likely_false_positive) with evidence for each."

Launch Agent 2 (finding-verifier, background):
  "You are verifying HIGH findings for {domain}. Session: {session}.
  
  For each finding, re-send the poc_request:
  {high_findings_json}
  
  Return: updated status with evidence for each."

Launch Agent 3 (finding-verifier, background):
  "You are verifying MEDIUM/LOW findings for {domain}. Session: {session}.
  
  For each finding, re-send the poc_request:
  {other_findings_json}
  
  Return: updated status with evidence for each."
```

## Dispatch Pattern 4: Investigate + Continue

When scanning reveals an anomaly worth investigating:

```
Launch Agent 1 (payload-crafter, foreground — need results):
  "You are investigating a potential {vuln_type} on {domain}.
  Session: {session}. Target: {method} {path}?{param}
  
  The auto_probe returned score {score} with these anomalies: {anomalies}
  
  Follow the investigate skill:
  1. Establish baseline behavior
  2. Map what characters/keywords are filtered
  3. Try context-specific payloads
  4. If filter found, use craft-payload approach to build bypass
  5. Verify any working payload 2-3 times
  
  Return: confirmed finding with evidence, OR 'false positive' with explanation."

Launch Agent 2 (vuln-scanner, background — continue the hunt):
  "You are continuing vulnerability scanning for {domain}.
  Session: {session}.
  
  Test the next category ({next_category}) on these targets:
  {next_targets_json}
  
  Use: auto_probe or bulk_test as appropriate.
  
  Return: findings with scores."
```

## Dispatch Pattern 5: Full Parallel Recon + Edge Testing

For a comprehensive first pass:

```
Launch Agent 1 (recon-agent, background):
  "Map attack surface: discover_attack_surface + discover_common_files"

Launch Agent 2 (js-analyst, background):
  "Analyze JavaScript: fetch_page_resources + extract_js_secrets + analyze_dom"

Launch Agent 3 (vuln-scanner, background):
  "Test edge cases: test_cors + test_graphql (if /graphql exists) + test_jwt (if JWT auth)"
```

## Prompt Template Best Practices

When dispatching agents, always include:

1. **Domain and session name** — agent needs these to call MCP tools
2. **Specific targets** — exact endpoints/parameters, not "find them yourself"
3. **What tools to use** — don't make the agent guess
4. **What to return** — structured result format
5. **What NOT to do** — prevent agents from going off-script
6. **Evidence requirements** — for verifier agents

**Good prompt:**
```
"You are a SQL injection scanner for example.com. Session: 'target1'.

Test these 5 endpoints for SQLi:
[{"method":"GET","path":"/api/users","parameter":"id","baseline_value":"1","location":"query"},
 {"method":"GET","path":"/api/products","parameter":"pid","baseline_value":"100","location":"query"}]

Use: auto_probe(session='target1', targets=ABOVE, categories=['sqli'])

For any finding with score >= 30, re-send the payload to confirm timing or error.

Return: JSON array of findings. Do NOT test other vuln types. Do NOT modify the session."
```

**Bad prompt:**
```
"Test example.com for vulnerabilities."  # Too vague, will waste tokens exploring
```

## Merging Results

After agents complete, the orchestrator must:

1. **Collect all findings** into a single list
2. **Deduplicate** — same endpoint + same vuln type = keep highest score
3. **Sort by severity** — CRITICAL first
4. **Identify investigation candidates** — score 30-50 anomalies
5. **Update memory:**
   ```python
   save_target_intel(domain, "findings", merged_findings)
   save_target_intel(domain, "coverage", merged_coverage)
   ```
6. **Present to user** — show the combined dashboard

## Efficiency Gains

| Approach | Sequential | Parallel (agents) | Speedup |
|---|---|---|---|
| Full recon | 6 calls, ~2 min | 2 agents, ~1 min | 2x |
| 4 vuln categories | 20 calls, ~5 min | 4 agents, ~2 min | 2.5x |
| Verify 6 findings | 12 calls, ~3 min | 3 agents, ~1.5 min | 2x |
| Full hunt (recon + test + verify) | 50+ calls, ~15 min | Phased parallel, ~6 min | 2.5x |

The real gain isn't just wall-clock time — it's **context window preservation**. Each agent uses its own context, so the orchestrator's context stays clean for strategic decisions.
