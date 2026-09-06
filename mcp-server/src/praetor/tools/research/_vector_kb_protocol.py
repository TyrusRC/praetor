"""Request/parse/protocol class deep-dive prompts (csrf/xxe/race/smuggling/deserialization/open_redirect).

Data slice re-assembled by _vector_kb.py — do not import directly.
"""

from __future__ import annotations


_PROTOCOL: dict[str, dict[str, list[str]]] = {
    "csrf": {
        "deep_dive": [
            "Token mechanism: synchronizer / double-submit cookie / SameSite cookie / Origin+Referer / custom header.",
            "Token tied to user? Or static per session? Or just `csrf_token=<random>` without binding.",
            "Endpoint method-validation: does the same handler accept GET as POST?",
            "Cross-site GET that mutates state — REST violations are CSRF gold.",
            "SameSite=Lax has carve-outs (top-level GET, anchor-tag) — exploitable for some flows.",
        ],
        "obscure": [
            "CSRF on logout — combine with a separate XSS / login-CSRF for session-fixation chain.",
            "JSON endpoints often skip CSRF check assuming Content-Type protects them — but text/plain works.",
            "Multipart endpoints — form-data hides intent, common bypass.",
            "GraphQL mutation endpoints — often no CSRF when Content-Type is application/json AND CORS is set right.",
            "OAuth state-less callbacks — login CSRF possible if attacker provides their auth code.",
        ],
        "chain": [
            "CSRF email change → password reset to attacker email → ATO.",
            "CSRF on 2FA-disable → ATO after credential phish.",
            "Login CSRF + post-auth stored XSS → trigger XSS in victim's session.",
            "CSRF on permissions change → privilege escalation.",
        ],
    },
    "xxe": {
        "deep_dive": [
            "Parser: libxml2 (PHP/Python/Ruby), Xerces (Java), MSXML — each has different default-entity behavior.",
            "Out-of-band: parameter-entity OOB via external DTD — exfils file contents via DNS/HTTP callback.",
            "Blind XXE via error-based: read file → embed in invalid DOCTYPE → server logs error with content.",
            "XInclude when DOCTYPE is filtered — same primitive, different syntax.",
            "OOXML / DOCX / XLSX uploads — contain XML, often parsed server-side.",
        ],
        "obscure": [
            "SVG upload + server-side render — XML inside, parsers often XXE-vulnerable.",
            "WS-Security SOAP — XXE in security tokens.",
            "PDF metadata (XMP) — XML inside, sometimes parsed.",
            "SAML response XML — parsed by IdP/SP libraries; signature wrapping + XXE combos.",
            "GraphQL endpoints accepting XML content-type (rare but seen).",
        ],
        "chain": [
            "XXE file read → SSH key → lateral movement.",
            "XXE → SSRF via http:// in entity → cloud metadata.",
            "XXE → /proc/self/environ → secrets in env vars.",
            "Blind XXE → DNS exfil of /etc/passwd via param-entity DTD.",
        ],
    },
    "race_condition": {
        "deep_dive": [
            "Last-byte sync (Burp's repeater group / send_to_intruder_configured / test_race_condition) for HTTP/1.1 latch.",
            "HTTP/2 single-packet attack — multiple requests in one TCP frame.",
            "Locking model: optimistic (compare-and-swap on version) / pessimistic (row lock) / none (TOCTOU).",
            "Money / quota / vote / claim operations — primary race targets.",
            "Concurrent-state mutations: redeem code N times in parallel.",
        ],
        "obscure": [
            "Race in OTP verification — submit OTP attempts in parallel, bypass rate limit by latch.",
            "Race in 2FA enrollment — disable+enroll new device in flight.",
            "Race in payment confirmation — confirm before merchant lock acquired.",
            "Race in account creation — register same email twice → which wins?",
            "Race in file upload + scan — race the AV scan before quarantine.",
        ],
        "chain": [
            "Race to claim invite code N times → privilege boost.",
            "Race in withdraw → balance underflow → infinite money.",
            "Race + IDOR → claim someone else's resource then race-confirm.",
            "Race in OAuth state validation → cross-account session.",
        ],
    },
    "request_smuggling": {
        "deep_dive": [
            "CL.TE / TE.CL / TE.TE / CL.0 / TE.0 / H2.CL / H2.TE / H2.0 — exact desync class matters.",
            "Frontend / backend stack identification: ALB / CloudFront / Cloudflare / Akamai / Fastly / Varnish / nginx / Apache.",
            "HTTP/2 → HTTP/1.1 downgrade smuggling — newer attack surface (2022+).",
            "Connection pooling — backend keeps connection open; smuggled prefix lands on next user.",
            "Cache poisoning chain — smuggled response cached at frontend.",
        ],
        "obscure": [
            "CL.0 (Content-Length zero) — frontend forwards body, backend ignores.",
            "Pseudo-header smuggling on HTTP/2 (transfer-encoding, content-length pseudo).",
            "WebSocket upgrade smuggling — upgrade hijack via 101.",
            "TE: chunked with non-standard chunk extensions / trailers.",
            "Backend tolerates `Content-Length: 0\\r\\nTransfer-Encoding: chunked\\r\\n`.",
        ],
        "chain": [
            "Smuggling → cache poisoning → mass session hijack.",
            "Smuggling → credential capture from next-user requests (steal cookies/auth).",
            "Smuggling → bypass front-end auth on internal admin paths.",
            "Smuggling + open redirect → MITM cookie injection.",
        ],
    },
    "deserialization": {
        "deep_dive": [
            "Format: Java serialized (AC ED 00 05 magic), .NET BinaryFormatter, PHP unserialize, Python pickle, Ruby Marshal, Node node-serialize/serialize-javascript.",
            "Gadget chain — needs existing class on classpath; ysoserial covers Java common chains.",
            "Pre-auth vs post-auth — pre-auth deserial in cookie/session is highest impact.",
            "JNDI lookup (Log4Shell family) via deserialization gadgets.",
            "JSON deserial with type info (Jackson @JsonTypeInfo, Newtonsoft TypeNameHandling) — also dangerous.",
        ],
        "obscure": [
            "ViewState deserialization (.NET) — needs machine key but sometimes leaked.",
            "Redis SET with serialized value — deserialized on read.",
            "MQ payloads (RabbitMQ / Kafka / SQS) — receiver deserializes.",
            "PHP phar:// stream wrapper — triggers unserialize on file ops.",
            "Spring Java DeferredImportSelector / proxy chains — gadgets in unexpected places.",
        ],
        "chain": [
            "Deserial → RCE → reverse shell → wider compromise.",
            "Deserial in session cookie → ATO of any user.",
            "Deserial in MQ → worker pool RCE → DB credentials.",
            "Deserial → JNDI → LDAP-served class load → RCE.",
        ],
    },
    "open_redirect": {
        "deep_dive": [
            "Parameter source: query / form / cookie / header / fragment.",
            "Filter bypasses: //evil.com (protocol-relative), https://evil.com, http://evil.com\\@target, IDN, encoded slashes, double-encoded.",
            "OAuth state/redirect_uri parameter — chain to token theft (most reportable form).",
            "JavaScript redirect (window.location=) vs Location header — different filter surfaces.",
            "Allowlist on prefix only — //target.com.evil.com or //target.com@evil.com.",
        ],
        "obscure": [
            "Redirect in /logout?next= → CSRF + open-redirect → phish login post-logout.",
            "Single Sign-On redirect_uri without strict match — token theft.",
            "Whitelist-by-substring — target.com matches malicious-target.com.tld.",
            "Open redirect via path traversal in redirect target.",
            "Server-side ?url= for thumbnail/preview — open redirect + SSRF combo.",
        ],
        "chain": [
            "OAuth redirect_uri laxity → token leak → ATO (HIGH/CRITICAL).",
            "Open redirect on password reset link → credential phish.",
            "Open redirect → exfil session via Referer header.",
            "Open redirect alone is NEVER-SUBMIT — must chain.",
        ],
    },
}
