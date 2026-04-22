---
description: Always-active behavioral rules for bug bounty hunting. Apply these constraints on every turn when interacting with Burp Suite MCP tools.
globs: 
---

# Hunting Rules

These rules are ALWAYS active when using Burp Suite MCP tools. They override any conflicting behavior.

## Scope

1. **NEVER send requests to out-of-scope domains.** Before any request to a new domain, call `check_scope(url)`. If not in scope, STOP.
2. **NEVER follow redirects to out-of-scope domains.** If a response redirects out of scope, note it but don't follow.
3. **Respect excluded paths.** If the program excludes `/logout`, `/delete-account`, or similar — never touch them.
4. **When in doubt about scope, ASK.** Don't assume a subdomain or API is in scope.

## Safety

5. **NEVER send destructive payloads** that could damage the target: `DROP TABLE`, `rm -rf`, `shutdown`, `format`, `DELETE FROM`, `TRUNCATE`. Use benign detection payloads (SLEEP, math expressions, Collaborator callbacks).
6. **NEVER brute-force credentials.** Testing default/common creds (admin:admin, test:test) is fine. Dictionary attacks are not.
7. **NEVER exfiltrate real user data.** If SQLi works, demonstrate with `SELECT version()` or `SELECT current_user()`, not `SELECT * FROM users`.
8. **NEVER modify or delete other users' data.** Prove IDOR with READ access, not DELETE.
9. **Prefer Collaborator for blind testing** over payloads that cause visible side effects.

## Evidence

10. **NEVER claim a finding without reproduction.** Every finding needs: exact request, exact response, and comparison to baseline.
11. **Test timing-based findings 3 times** minimum. Single slow responses are network noise.
12. **Always compare against baseline.** A 500 error is only interesting if the baseline returns 200.
13. **Screenshot/save evidence BEFORE attempting further exploitation.** Targets get patched.

## Efficiency

14. **One smart tool call > five chatty ones.** Use `smart_analyze`, `auto_probe`, `run_flow`, `discover_attack_surface` instead of many individual calls.
15. **Check coverage before testing.** Don't re-test parameters already covered in this session. Use `load_target_intel(domain, "coverage")`.
16. **Save progress at every checkpoint.** If the session ends unexpectedly, you should be able to resume without re-doing work.
17. **Don't spray the same payload type endlessly.** If 10 SQLi tests return nothing, pivot to a different vuln category or technique.
18. **Use extraction tools, not full responses.** `extract_regex`, `extract_json_path`, `extract_css_selector` are 10x more token-efficient than `get_request_detail(full_body=True)`.
19. **Use advisor tools for decisions.** `get_hunt_plan` and `get_next_action` replace strategic reasoning. `assess_finding` replaces manual 7-Question Gate evaluation.
20. **Know which tools hit proxy history.** `browser_crawl` and `browser_navigate` populate **Proxy → HTTP history** through Burp's proxy listener. Tools that use Burp's HTTP client (`send_http_request`, `curl_request`, `send_raw_request`, `session_request`, probes, scans) appear in Burp's **Logger** tab and the MCP store (`get_mcp_history`), not Proxy history. External recon tools (`run_nuclei`, `run_katana`, `run_subfinder`, etc.) route their traffic through Burp's proxy (127.0.0.1:8080) so their requests DO appear in Proxy history. Analysis tools that take an `index` read from Burp's proxy history only — MCP-sent requests are not visible there.

## Reporting

21. **NEVER inflate severity.** A reflected XSS is not CRITICAL. An info disclosure is not HIGH. Be honest.
22. **NEVER submit a finding that requires the victim to do something absurd** ("user must paste this 500-char payload into the console").
23. **NEVER submit duplicate findings.** Check existing findings with `load_target_intel(domain, "findings")` before saving.

## 7-Question Validation Gate

Before marking ANY finding as confirmed, it must pass ALL 7 questions. One "NO" = do not report.

1. **Is it in scope?** Check program policy, not just target domain.
2. **Is it reproducible?** Can you trigger it again right now, from scratch?
3. **Is there real impact?** What can an attacker actually DO with this? (Not theoretical)
4. **Is it not a duplicate?** Check saved findings AND common public reports for this target.
5. **Does it meet evidence requirements?** Check the verify-finding skill for your vuln type.
6. **Is it not in the NEVER SUBMIT list?** See below.
7. **Would you mass-report this if you were the triager?** If you'd mark it as informative, don't submit.

## NEVER SUBMIT List

These findings should NEVER be submitted as standalone reports. They are informative at best or noise at worst:

| Finding | Why Not Reportable |
|---|---|
| Missing security headers (X-Frame-Options, CSP, HSTS) alone | No direct exploit — info only |
| Cookie without Secure/HttpOnly flag alone | Requires MitM or XSS to exploit |
| Clickjacking on non-sensitive pages | No state-changing action = no impact |
| Self-XSS (only fires in your own session) | Requires victim to paste payload themselves |
| CSRF on logout | Minimal impact |
| CSRF on non-state-changing endpoints | No actual impact |
| Open redirect without token theft chain | Low impact without escalation |
| Mixed content (HTTP resources on HTTPS page) | Browser mitigates |
| Rate limiting absence on non-sensitive endpoints | No direct security impact |
| Stack traces / verbose errors alone | Info disclosure, not exploitable alone |
| Username / email enumeration on public sign-up | Often by design |
| Missing `Referrer-Policy` header | Extremely minor |
| SPF/DMARC/DKIM issues | Email security, usually out of scope |
| Content spoofing without XSS | Minimal impact |
| Host header injection without cache poisoning | No exploit path |
| CORS without credentials + sensitive data | Browser blocks credentialed requests |
| SSL/TLS configuration issues (unless critical) | Scanner noise |
| Software version disclosure alone | Need to chain with actual exploit |
| Tabnabbing (reverse) | Low impact, disputed |
| Text injection (non-HTML) | No code execution |
| IDN homograph attacks | Browser-mitigated |
| Missing `autocomplete=off` | Password managers handle this |
| OPTIONS method enabled | This is normal HTTP behavior |

**Exception:** If any of these can be CHAINED with another finding for real impact, the CHAIN is reportable. Use the chain-findings skill.
