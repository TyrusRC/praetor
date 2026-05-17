"""research_attack_vector — curated research bundle for any vuln class.

This tool does NOT call the internet. It returns a structured packet of
URLs + class-specific deep-dive prompts. The caller (Claude) then uses
WebFetch on the high-signal URLs to read writeups, hacktivity reports,
and PortSwigger research — at the point in the hunt where it matters,
not as a precomputed dump.

Why this exists
---------------
Rule 27 mandates ≥20% of every session goes to open-ended exploration
beyond the knowledge-base classes. The hard part isn't running auto_probe
— it's asking "what would an experienced researcher do with this finding
that I'm not thinking of?". This tool encodes that brain-dump as a single
call so Claude can stay in flow.

Output shape
------------
1. Deep-dive checklist — class-specific attack vectors that go beyond the
   obvious. Encoded once here so the prompts stay sharp across sessions.
2. Disclosed-reports URLs — pre-built searches for HackerOne hacktivity,
   GitHub PoC repos, Bug Bounty Reports archive. WebFetch the top hits.
3. Writeup-hub URLs — site-restricted Google searches for the major
   research blogs (PortSwigger, Doyensec, NCC, Assetnote, Detectify, etc.).
4. Code-pattern search — GitHub code-search URLs for the vulnerable
   primitive in similar tech (when tech_stack supplied).
5. Chain hypotheses — "if you can do X, try Y" derived from typical
   escalation paths for the class.
6. Next MCP calls — concrete tool invocations that complement the
   research (search_cve, map_tech_to_cves, get_payloads, auto_probe with
   specific categories).
"""

from __future__ import annotations

from urllib.parse import quote_plus

from mcp.server.fastmcp import FastMCP


# ─────────────────────────────────────────────────────────────────────────
# Class-specific deep-dive prompts
# ─────────────────────────────────────────────────────────────────────────
# Each entry: deep_dive (open-ended exploration questions), obscure
# (vectors operators commonly miss), chain (what the bug enables).
# Keep tight — these are loaded inline; bloating burns tokens on every call.

_VECTOR_KB: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "deep_dive": [
            "Backend RDBMS? Pg/MySQL/MSSQL/Oracle/SQLite each have unique funcs (version(), @@version, ::regclass, sqlite_master).",
            "ORM in use? Sequelize/Hibernate/Django ORM — sometimes raw($query) sinks bypass param binding.",
            "Second-order injection: payload stored via endpoint A, triggered by endpoint B.",
            "JSON column injection (Pg @>, MySQL ->>) — params inside JSON often bypass naive filters.",
            "Stacked queries on MSSQL/Pg — separator ; lets you EXEC xp_cmdshell or pg_sleep().",
            "Out-of-band exfil via DNS (UTL_HTTP, LOAD_FILE INTO OUTFILE, master..xp_dirtree) for blind cases.",
        ],
        "obscure": [
            "ORDER BY injection — accepts column name, not value; classic filter bypass spot.",
            "GROUP_CONCAT length truncation on MySQL — split UNION SELECT into chunks.",
            "LIMIT clause injection — works on MySQL with `LIMIT 1 PROCEDURE ANALYSE(EXTRACTVALUE(...))`.",
            "INSERT/UPDATE INTO injection — payload reaches a different table than you expect.",
            "Bypass via SQL comments: /*!50000union*/, /*!*/select, --+ vs --%20.",
        ],
        "chain": [
            "RCE on MSSQL via xp_cmdshell after sysadmin escalation.",
            "RCE on MySQL via INTO OUTFILE → webshell upload (if FILE priv + writable webroot).",
            "Data exfil → user table dump → cred-stuffing other surfaces.",
            "SSRF via UTL_HTTP (Oracle), pg_read_server_files (Pg ≥ 11).",
        ],
    },
    "xss": {
        "deep_dive": [
            "Sink type: innerHTML / document.write / location / eval / setTimeout-with-string / DOM event handler attr.",
            "CSP present? Decode and check for unsafe-inline, unsafe-eval, wildcard hosts, JSONP endpoints, ANGULAR pattern.",
            "Mutation XSS (mXSS) — innerHTML re-parsing after sanitization (DOMPurify ≤ certain versions).",
            "Postmessage XSS — origin check too loose? wildcard targetOrigin?",
            "Self-XSS to stored XSS via account-takeover-style csrf or cors.",
        ],
        "obscure": [
            "SVG <use href=...> XSS — animated SVGs bypass naive sanitizers.",
            "JSON-content-type reflected XSS via UTF-7 / content-sniffing (old IE / Safari).",
            "PDF rendering XSS via /JS embed (Chrome PDF reader has run code historically).",
            "Markdown/MDX injection — image syntax that runs JS via on-error or javascript: URI.",
            "Server-rendered template that auto-escapes HTML but NOT attributes — break out of attr context.",
        ],
        "chain": [
            "XSS → fetch /api/me → exfil session token to attacker.",
            "XSS → CSRF email change → ATO (chain raises severity from MEDIUM to CRITICAL).",
            "Stored XSS in admin-viewed page → admin ATO → full platform compromise.",
            "XSS → grab anti-CSRF token → make state-changing request.",
        ],
    },
    "ssrf": {
        "deep_dive": [
            "Cloud provider? AWS (169.254.169.254 + IMDSv2 token), GCP (metadata.google.internal + custom header), Azure (169.254.169.254 + Metadata:true), Alibaba/Oracle/DO each have own endpoint.",
            "Protocol smuggling — gopher:// for Redis/Memcached RCE, dict:// for service probing, file:// for arbitrary read, jar:// (Java) for zip slip.",
            "DNS rebinding — does the app re-resolve the URL between check and use? TOCTOU.",
            "Header injection (X-Forwarded-For, Host, Origin) reaching upstream HTTP client.",
            "Parser confusion: URL `http://evil.com#@127.0.0.1/` — bypass with @, .., %2e, IDN homographs.",
        ],
        "obscure": [
            "Webhook URL acceptance — slack/discord-style integration endpoints often SSRF.",
            "Image proxy / favicon fetcher / OpenGraph preview / PDF generator (wkhtmltopdf, weasyprint).",
            "SAML / OIDC metadata URL — gateway often fetches without filtering.",
            "Server-side JS rendering (Node.js with playwright/puppeteer) — page.goto() to internal IP.",
            "Blind SSRF via DNS exfil — append unique subdomain to Collaborator.",
        ],
        "chain": [
            "SSRF → IMDSv1 → AWS temp creds → S3 / DynamoDB / Lambda invocation.",
            "SSRF → internal admin panel without auth → ATO.",
            "SSRF → Redis (gopher) → SET ssh key → RCE.",
            "SSRF → Kubernetes API token (/var/run/secrets/...) → cluster takeover.",
        ],
    },
    "ssti": {
        "deep_dive": [
            "Engine? Jinja2 / Twig / FreeMarker / Velocity / Smarty / ERB / Mako / Tornado / Thymeleaf / SpEL / Pebble / Handlebars / Pug / Nunjucks / Liquid — each has distinct exploit chain.",
            "Sandbox enabled? Jinja2 SandboxedEnvironment / Twig SandboxExtension / SpEL SimpleEvaluationContext.",
            "Class polluation paths: Python `__class__.__mro__[1].__subclasses__()` index varies per Python version.",
            "Server-rendered email templates / PDF-from-HTML — often higher-trust render with fewer escapes.",
            "Two-stage render: param stored as template fragment, second render evaluates.",
        ],
        "obscure": [
            "Markdown/MJML/AsciiDoc engines with template inclusion ({{> partial}}).",
            "i18n message format strings (Java MessageFormat, ICU) — accept arg{0} but also expressions.",
            "Spring Thymeleaf Spring EL preprocessing `__${...}__::.x` syntax — bypasses naive {{ }} filters.",
            "Object-graph traversal in Velocity: $class.inspect(\"java.lang.Runtime\").type — even with sandboxes.",
            "Pebble RCE via `(1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(...)` reflection chain.",
        ],
        "chain": [
            "SSTI → confirm via {{7*7}} → escalate to RCE via engine-specific OS exec → root via container escape.",
            "SSTI in email template → exfil SECRET_KEY → forge session cookies → ATO.",
            "SSTI in PDF-from-HTML → file read of /etc/passwd, /proc/self/environ, .env.",
            "SSTI → cloud metadata read → temp creds → wider compromise.",
        ],
    },
    "idor": {
        "deep_dive": [
            "ID format: sequential int / UUIDv1 (timestamp-based, predictable) / UUIDv4 (random) / encoded (base64, hashids).",
            "Authorization layer: pre-controller filter / per-handler check / ORM scope / row-level security (DB).",
            "GraphQL vs REST: same data often exposed in GQL without REST's auth filter.",
            "Bulk endpoints / export endpoints — auth often weaker than per-item GET.",
            "Inactive/legacy API versions (v1, v2-deprecated) — fewer auth checks.",
        ],
        "obscure": [
            "UUIDv1 monotonicity — given one UUID and timestamp, predict adjacent IDs.",
            "Encoded IDs (rot13, custom base, hashids without secret) — predict via known transform.",
            "PUT/PATCH/DELETE on read-protected resource: GET 403 but DELETE 200.",
            "Filter param IDOR: /api/items?owner_id=<other_user>.",
            "Reference object IDs in nested JSON: {parent_id: X, ...} — server trusts the embedded ID.",
        ],
        "chain": [
            "IDOR list endpoint → PII enumeration → GDPR-class report.",
            "IDOR on settings → email change → password reset → ATO.",
            "IDOR on file/document → confidential data exfil.",
            "IDOR + mass assignment → privilege escalation (set role=admin).",
        ],
    },
    "rce": {
        "deep_dive": [
            "Sink: subprocess / os.system / eval / exec / unserialize / Runtime.exec / child_process / Process.Start.",
            "Argument vs shell: shell=True splits on spaces (injectable), shell=False with array is safer (but argument injection via -arg still possible).",
            "Container escape post-RCE: /proc/1/root, /var/run/docker.sock, /run/secrets/kubernetes.io/serviceaccount/token.",
            "Filter bypasses: $(...) vs `...`, ${IFS} for space, base64-decoded exec, tee | sh staging.",
            "Wildcards: `tar cf - *` with `--checkpoint-action=exec=sh` (the wildchar trick).",
        ],
        "obscure": [
            "Argument injection without shell — find a CLI that has an --output= or --eval= flag.",
            "Log4Shell-class JNDI lookups still alive in non-Java services (Logback, syslog formatters).",
            "Deserialization gadgets — ysoserial chains, PHP unserialize POP chains, Python pickle.",
            "PostgreSQL `COPY ... FROM PROGRAM` → RCE if you have CREATE on a db.",
            "ImageMagick (CVE-2016-3714 family) — still found in image-upload pipelines.",
        ],
        "chain": [
            "RCE → reverse shell → lateral movement → AWS metadata → environment-wide compromise.",
            "RCE → reverse shell → /etc/shadow / SSH key extraction.",
            "RCE in container → check for capabilities (CAP_SYS_ADMIN, privileged), break out.",
            "RCE → modify deploy config → persistence across redeploys.",
        ],
    },
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
    "prototype_pollution": {
        "deep_dive": [
            "Sink: lodash merge / extend / defaultsDeep, jQuery extend, custom deep-merge, JSON.parse + assign.",
            "Trigger: query string parser (qs, body-parser), JSON.parse, deep-merge of request body.",
            "Gadget chains: ejs render, command-line args, csurf token check — class-specific gadgets.",
            "Server-side vs client-side — server-side enables RCE via gadget; client-side typically XSS.",
            "Polluting via path notation: __proto__[x]=y, constructor[prototype][x]=y, nested merge.",
        ],
        "obscure": [
            "GraphQL variables → server-side merge → prototype pollution.",
            "CSV / XML / YAML body parsers with nested key support.",
            "Express body-parser with `parameterLimit` raised — large nested objects.",
            "WebSocket message handlers that deep-merge state.",
            "Cache key construction using Object.keys — polluted keys appear.",
        ],
        "chain": [
            "Server PP → ejs gadget → RCE.",
            "Server PP → bypass auth check (default role injection).",
            "Server PP → cache poisoning via polluted cache key.",
            "Client PP → DOM XSS (gadget in jQuery / handlebars / marked).",
        ],
    },
    "auth_bypass": {
        "deep_dive": [
            "Auth layer: middleware ordering (does the protected path register before auth middleware?), per-route guard, gateway-level (Kong/Envoy).",
            "Header smuggling: X-Original-URL / X-Rewrite-URL / X-Forwarded-Path can bypass front-end auth.",
            "Path normalization: /admin/../user/admin /admin%2f /admin;.json /admin..;/ — gateway parses different than backend.",
            "Method confusion: GET protected but HEAD/OPTIONS/PROPFIND not.",
            "Trailing slash / case sensitivity / null byte — gateway vs backend mismatch.",
        ],
        "obscure": [
            "Sign-up endpoint accepts role / admin / is_admin field (mass assignment).",
            "Password reset OTP brute force without rate limit (numeric 4-digit = 10000 tries).",
            "JWT alg=none, RS→HS confusion, kid injection, jku/x5u, claim swap, weak HS secret.",
            "OAuth flow: implicit-grant token in URL fragment leaks via referer.",
            "SAML signature wrapping / unsigned assertion / signature exclusion.",
        ],
        "chain": [
            "Header smuggling → admin panel → ATO of all users.",
            "Path normalization → unauth endpoint → cred reset → ATO.",
            "Mass assignment role=admin on signup → admin panel access.",
            "JWT forge → impersonate any user → ATO.",
        ],
    },
    "graphql": {
        "deep_dive": [
            "Introspection enabled in prod? Query __schema, __type to map.",
            "Field-level auth or just operation-level? Often introspection is auth'd but field execution isn't.",
            "Batched queries — single HTTP request with N operations: bypass rate limit, race conditions.",
            "Aliasing — same field N times with aliases: amplify brute force.",
            "Deep nesting → DoS / amplification (`{me{posts{author{posts{author{...}}}}}`).",
        ],
        "obscure": [
            "Mutation that wraps DB writes without per-field authz check.",
            "Resolver that uses request context but trusts a body-supplied user_id.",
            "Persisted query bypass via injection of new query into operation_name.",
            "GraphQL CSRF: POST with non-JSON content-type + GET-style query in body.",
            "Schema-stitching gateways aggregating internal services — auth at edge only.",
        ],
        "chain": [
            "Introspection → discover privileged mutations → IDOR / mass assignment via GQL.",
            "Aliasing → brute force OTP without rate limit.",
            "Batched mutation → race condition.",
            "GraphQL DoS → cost-based outage chain.",
        ],
    },
    "websocket": {
        "deep_dive": [
            "Origin check on upgrade? Per CSWSH — if no Origin validation, attacker.com can open authenticated socket.",
            "Auth model: cookie at upgrade / token in URL / first-message handshake / subprotocol-bearer.",
            "Message-level auth: server trusts client claims or re-validates each message?",
            "Subprotocol negotiation — flaw in `Sec-WebSocket-Protocol` selection.",
            "Persistent connections survive logout / role change? (state desync).",
        ],
        "obscure": [
            "Token in URL query string at upgrade — leaks via Referer / logs / proxy history.",
            "Cross-site WebSocket hijacking is a classic still missed (per Snyk's 2023 reports).",
            "WS over HTTP/2 — upgrade semantics different, some gateways skip Origin check.",
            "Long-poll fallback (Socket.io) — Origin-check applied to WS but not poll.",
            "Subscription/streaming endpoints over WS expose more data than REST.",
        ],
        "chain": [
            "CSWSH → exfil real-time data feed (chat / orderbook / location).",
            "CSWSH + persistent socket → state desync after logout.",
            "WS without msg auth → IDOR-via-WS unsubscribed channels.",
            "WS subprotocol smuggling → backend service bypass.",
        ],
    },
    "cors": {
        "deep_dive": [
            "Reflected Origin? Wildcard? Subdomain trust? Null origin acceptance?",
            "Credentialed CORS (Access-Control-Allow-Credentials: true) + reflected origin = data exfil to attacker.",
            "Path-level CORS — different per route; only sensitive endpoints matter.",
            "Pre-flight cache (Access-Control-Max-Age) — bypass requires invalidating.",
            "Subdomain takeover + CORS trust on *.target.com = cross-domain data exfil.",
        ],
        "obscure": [
            "Origin: null acceptance — exploitable via sandboxed iframe / data: URI.",
            "Wildcard subdomain in allowlist matching by substring.",
            "Trailing-dot Origin (https://target.com.) sometimes bypasses regex.",
            "CORS misconfig with internal IP / localhost trust.",
            "Reflected Referer header used instead of Origin.",
        ],
        "chain": [
            "Reflected-Origin + credentials → exfil cookies/csrf token from victim → ATO.",
            "CORS on sensitive API + low-priv user → exfil higher-priv data.",
            "CORS misconfig + XSS on subdomain → exfil parent-domain data.",
        ],
    },
    "business_logic": {
        "deep_dive": [
            "Order-of-operations: step skipping (skip payment step) / step replay / step reorder.",
            "State machine: are state transitions enforced server-side?",
            "Price/quantity manipulation: negative numbers, decimals beyond schema, very large integers.",
            "Coupon/promo chaining — stack codes that shouldn't combine.",
            "Limits: subscription tier limits, daily/monthly caps — what happens if you race past them?",
        ],
        "obscure": [
            "Returns/refunds without product return — refund-only state.",
            "Subscription cancellation during a payment window — get the goods AND a refund.",
            "Multi-user resource transfer — transfer A→B→C; does each check?",
            "Loyalty point earning during reversal — earn points on a refunded purchase.",
            "Test/staging promo codes that work in prod.",
        ],
        "chain": [
            "Free product chain → revenue impact (reportable).",
            "Negative price → balance increase → withdraw to attacker.",
            "Race + business logic → impossible state → privilege upgrade.",
            "Subscription bypass → premium features → competitive harm.",
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────
# Two-tier source design
# ─────────────────────────────────────────────────────────────────────────
# 1. METHODOLOGY DEEP-LINKS — per-class direct URLs to verified-static-HTML
#    reference pages (PortSwigger Academy, HackTricks, PayloadsAllTheThings,
#    OWASP WSTG). WebFetch returns rich content reliably. Curated, stable.
#
# 2. SUGGESTED SEARCH QUERIES — pre-baked WebSearch queries Claude pipes to
#    its native WebSearch tool. Avoids hardcoded URLs that get blocked,
#    JS-rendered SPAs (H1 hacktivity, OpenBugBounty, Bugcrowd Crowdstream),
#    Cloudflare challenges (NCC, CISA KEV), and dead aggregators. Search
#    engines do the routing; we just supply the right keywords.
#
# Sources verified live for HTTP 200 + non-shell HTML content (Dec 2026):
#   STATIC HTML (WebFetch works):
#     portswigger.net/web-security/*  — Academy, full content
#     book.hacktricks.xyz/*           — GitBook static
#     github.com/swisskyrepo/...      — GitHub static tree
#     owasp.org/www-project-...       — OWASP project pages
#     pentester.land                  — Hugo static
#     portswigger.net/research        — research index
#     blog.doyensec.com               — Jekyll static
#     blog.trailofbits.com            — Wordpress static
#     googleprojectzero.blogspot.com  — Blogger
#     samcurry.net, 0xpatrik.com, rcesecurity.com — personal blogs
#     exploit-db.com/search           — server-side rendered, returns results
#     osv.dev/list                    — server-rendered list
#     security.snyk.io/vuln           — server-rendered search
#     attackerkb.com/search           — server-rendered
#     github.com/advisories           — GitHub server-rendered
#
#   FAILED (do NOT hardcode):
#     hackerone.com/hacktivity        — SPA shell, JS-required
#     openbugbounty.org/search        — 403 Cloudflare
#     research.nccgroup.com           — 403 Cloudflare
#     cisa.gov/known-exploited-...    — 403
#     bugbountydoc.com                — dead (NXDOMAIN/timeout)
#     bug-bounty-disclosed.gitbook.io — 404
#     infosecwriteups.com/search      — 403 Medium
#
#   For failed sources, Claude can still reach the content via WebSearch
#   (search engines crawl them and return excerpts).

# Tier 1 — per-class methodology deep-links (verified static HTML)
_METHODOLOGY_LINKS: dict[str, dict[str, str]] = {
    "sqli": {
        "portswigger": "https://portswigger.net/web-security/sql-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/sql-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    },
    "xss": {
        "portswigger": "https://portswigger.net/web-security/cross-site-scripting",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
    },
    "ssrf": {
        "portswigger": "https://portswigger.net/web-security/ssrf",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
    },
    "ssti": {
        "portswigger": "https://portswigger.net/web-security/server-side-template-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    },
    "idor": {
        "portswigger": "https://portswigger.net/web-security/access-control",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/idor",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    },
    "rce": {
        "portswigger": "https://portswigger.net/web-security/os-command-injection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/command-injection",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
    },
    "csrf": {
        "portswigger": "https://portswigger.net/web-security/csrf",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
    },
    "xxe": {
        "portswigger": "https://portswigger.net/web-security/xxe",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
    },
    "race_condition": {
        "portswigger": "https://portswigger.net/web-security/race-conditions",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/race-condition",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition",
        "owasp":       "",
    },
    "request_smuggling": {
        "portswigger": "https://portswigger.net/web-security/request-smuggling",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/http-request-smuggling",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling",
        "owasp":       "",
    },
    "deserialization": {
        "portswigger": "https://portswigger.net/web-security/deserialization",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/deserialization",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization",
        "owasp":       "",
    },
    "open_redirect": {
        "portswigger": "https://portswigger.net/web-security/all-labs#open-redirection",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/open-redirect",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
    },
    "prototype_pollution": {
        "portswigger": "https://portswigger.net/web-security/prototype-pollution",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution",
        "owasp":       "",
    },
    "auth_bypass": {
        "portswigger": "https://portswigger.net/web-security/authentication",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/login-bypass",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
    },
    "graphql": {
        "portswigger": "https://portswigger.net/web-security/graphql",
        "hacktricks":  "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection",
        "owasp":       "",
    },
    "websocket": {
        "portswigger": "https://portswigger.net/web-security/websockets",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/websocket-attacks",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
    },
    "cors": {
        "portswigger": "https://portswigger.net/web-security/cors",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/cors-bypass",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Cross_Origin_Resource_Sharing",
    },
    "business_logic": {
        "portswigger": "https://portswigger.net/web-security/business-logic-vulnerabilities",
        "hacktricks":  "https://book.hacktricks.xyz/pentesting-web/business-logic-vulnerabilities",
        "patt":        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic",
        "owasp":       "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README",
    },
}

# Tier 2 — direct-search URLs to verified server-rendered databases.
# These return real content (not JS shells) and aren't bot-blocked.
# Each builder returns a single URL Claude can WebFetch directly OR pipe
# through WebSearch (both work).
def _exploitdb_search(query: str) -> str:
    return f"https://www.exploit-db.com/search?text={quote_plus(query)}"

def _osv_search(query: str) -> str:
    return f"https://osv.dev/list?q={quote_plus(query)}"

def _github_advisory_search(query: str) -> str:
    return f"https://github.com/advisories?query={quote_plus(query)}"

def _snyk_db_search(query: str) -> str:
    return f"https://security.snyk.io/vuln/?search={quote_plus(query)}"

def _attackerkb_search(query: str) -> str:
    return f"https://attackerkb.com/search?q={quote_plus(query)}"

def _github_code_search(query: str) -> str:
    return f"https://github.com/search?q={quote_plus(query)}&type=code"


# ─────────────────────────────────────────────────────────────────────────
# Tool registration
# ─────────────────────────────────────────────────────────────────────────

def register(mcp: FastMCP):

    @mcp.tool()
    async def research_attack_vector(
        vuln_type: str,
        tech_stack: str = "",
        finding_summary: str = "",
        endpoint: str = "",
        target_domain: str = "",
    ) -> str:
        """Curated security-research bundle for a suspected attack vector.

        Returns four sections: (1) deep-dive prompts + obscure vectors +
        chain hypotheses (from inline KB), (2) verified-static methodology
        deep-links (PortSwigger Academy + HackTricks + PayloadsAllTheThings
        + OWASP WSTG) Claude can WebFetch, (3) pre-baked WebSearch queries
        Claude pipes to its native search tool to reach JS-SPA / bot-blocked
        sources (HackerOne reports, Bugcrowd disclosures, writeup blogs)
        via search engines, (4) direct advisory-DB URLs (Exploit-DB / OSV /
        GitHub Advisory / Snyk DB / AttackerKB).

        Hardcoded URLs are ONLY used for sources verified to return rich
        non-JS content. Everything else routes through WebSearch — search
        engines crawl them and we get content without fighting Cloudflare.

        Use when you found something interesting but aren't sure how deep
        it goes — this tool encodes "what would a senior researcher try?"
        as a single call. Rule 27's 20%-creative-hunting budget lives here.

        Args:
            vuln_type: Class (sqli, xss, ssrf, ssti, idor, rce, csrf, xxe,
                race_condition, request_smuggling, deserialization,
                open_redirect, prototype_pollution, auth_bypass, graphql,
                websocket, cors, business_logic). Free-form accepted.
            tech_stack: Comma-separated tech identifiers — "express,redis"
                / "django,postgres" / "spring-boot,kafka". Narrows code
                search + advisory-DB queries.
            finding_summary: One-sentence observation. Used verbatim in
                some search queries for highest-signal matches.
            endpoint: Endpoint that triggered the suspicion. Optional.
            target_domain: Bug-bounty target host. If supplied, adds a
                "priors on this target" search query.
        """
        v = (vuln_type or "").lower().strip()
        kb = _VECTOR_KB.get(v)
        # Build alias mapping for free-form
        if not kb:
            aliases = {
                "sql_injection": "sqli", "sqlinjection": "sqli",
                "cross_site_scripting": "xss",
                "server_side_request_forgery": "ssrf",
                "server_side_template_injection": "ssti",
                "remote_code_execution": "rce", "command_injection": "rce",
                "cross_site_request_forgery": "csrf",
                "xml_external_entity": "xxe",
                "http_request_smuggling": "request_smuggling", "smuggling": "request_smuggling",
                "insecure_deserialization": "deserialization",
                "openredirect": "open_redirect",
                "prototypepollution": "prototype_pollution", "proto_pollution": "prototype_pollution",
                "authentication_bypass": "auth_bypass", "auth": "auth_bypass",
                "broken_access_control": "auth_bypass",
                "race": "race_condition",
            }
            if v in aliases:
                v = aliases[v]
                kb = _VECTOR_KB.get(v)

        lines: list[str] = [
            f"=== Security Research Bundle: {vuln_type or '(unspecified)'} ===",
            "",
        ]
        if finding_summary:
            lines.append(f"Finding context: {finding_summary}")
            lines.append("")

        # ── Section 1: Deep-dive checklist ──────────────────────────
        if kb:
            lines.append(f"── DEEP-DIVE QUESTIONS ({v}) ──")
            for q in kb["deep_dive"]:
                lines.append(f"  Q: {q}")
            lines.append("")
            lines.append(f"── OBSCURE VECTORS ({v}) ──  (commonly missed)")
            for o in kb["obscure"]:
                lines.append(f"  • {o}")
            lines.append("")
            lines.append(f"── CHAIN HYPOTHESES ({v}) ──  (what this bug ENABLES)")
            for c in kb["chain"]:
                lines.append(f"  → {c}")
            lines.append("")
        else:
            lines.append(f"── No structured KB for '{vuln_type}'. Falling back to URL-only research bundle. ──")
            lines.append("")

        query_base = v.replace("_", " ") if kb else (vuln_type or "")

        # ── Section 2: Methodology deep-links (verified static HTML) ─
        meth = _METHODOLOGY_LINKS.get(v)
        if meth:
            lines.append(f"── METHODOLOGY DEEP-LINKS ({v}) — WebFetch directly ──")
            if meth.get("portswigger"):
                lines.append(f"  WebFetch  {meth['portswigger']}    # PortSwigger Web Security Academy")
            if meth.get("hacktricks"):
                lines.append(f"  WebFetch  {meth['hacktricks']}    # HackTricks book")
            if meth.get("patt"):
                lines.append(f"  WebFetch  {meth['patt']}    # PayloadsAllTheThings")
            if meth.get("owasp"):
                lines.append(f"  WebFetch  {meth['owasp']}    # OWASP WSTG")
            lines.append("")

        # ── Section 3: Pre-baked WebSearch queries ──────────────────
        # Use Claude's native WebSearch for sources that are JS-SPA /
        # bot-blocked / Cloudflare'd. Search engines crawl them and
        # return excerpts. We just supply the right keywords.
        lines.append("── SUGGESTED WEB SEARCHES — pipe through WebSearch ──")
        seed_specific = finding_summary or query_base or vuln_type

        # Disclosed reports (H1, Bugcrowd, Intigriti) via site dorks
        lines.append(f'  WebSearch  "{query_base} site:hackerone.com/reports"')
        lines.append(f'  WebSearch  "{query_base} bug bounty writeup 2024 2025"')
        if target_domain:
            lines.append(f'  WebSearch  "{target_domain} hackerone disclosed report"   # priors on this target')
            lines.append(f'  WebSearch  "{target_domain} bug bounty"')

        # Writeup aggregators (Medium / Pentester Land / personal blogs)
        lines.append(f'  WebSearch  "{query_base} site:infosecwriteups.com"')
        lines.append(f'  WebSearch  "{query_base} site:pentester.land"')

        # Research-blog deep dives (PortSwigger Research, Doyensec, Assetnote)
        lines.append(f'  WebSearch  "{query_base} site:portswigger.net/research"')
        lines.append(f'  WebSearch  "{query_base} site:blog.doyensec.com OR site:blog.assetnote.io OR site:samcurry.net"')

        # Tech-specific narrowing
        if tech_stack:
            for tech in [t.strip() for t in tech_stack.split(",") if t.strip()][:3]:
                lines.append(f'  WebSearch  "{query_base} {tech} CVE exploit"')
                lines.append(f'  WebSearch  "{query_base} {tech} bypass"')

        # Use finding_summary verbatim — high-signal phrase match
        if finding_summary and finding_summary != query_base:
            lines.append(f'  WebSearch  "{seed_specific}"   # exact-phrase precedent search')

        lines.append("")

        # ── Section 4: Advisory-DB direct URLs (server-rendered) ─────
        # These all return real HTML content (verified). WebFetch directly.
        lines.append("── ADVISORY DATABASES — WebFetch directly ──")
        adv_seed = (tech_stack.split(",")[0].strip() if tech_stack else query_base).strip()
        if adv_seed:
            lines.append(f"  WebFetch  {_exploitdb_search(adv_seed)}    # Exploit-DB")
            lines.append(f"  WebFetch  {_osv_search(adv_seed)}    # OSV.dev (Google's vuln DB)")
            lines.append(f"  WebFetch  {_github_advisory_search(adv_seed)}    # GitHub Advisory Database")
            lines.append(f"  WebFetch  {_snyk_db_search(adv_seed)}    # Snyk Vulnerability DB")
            lines.append(f"  WebFetch  {_attackerkb_search(adv_seed)}    # Rapid7 AttackerKB (exploit-in-the-wild intel)")
        lines.append("")

        # ── Section 5: GitHub code-pattern search ───────────────────
        if tech_stack:
            lines.append("── GITHUB CODE SEARCH — find similar vulnerable patterns ──")
            techs = [t.strip() for t in tech_stack.split(",") if t.strip()][:3]
            code_patterns = {
                "sqli": "raw query string",
                "xss": "innerHTML req.query",
                "ssrf": "axios.get req.body",
                "ssti": "render_template_string request",
                "idor": "findByPk req.params.id",
                "rce": "exec child_process req",
                "deserialization": "ObjectInputStream readObject",
                "prototype_pollution": "Object.assign req.body",
                "open_redirect": "res.redirect req.query",
            }
            pat = code_patterns.get(v, vuln_type)
            for tech in techs:
                q = f"{pat} language:{tech}".strip()
                lines.append(f"  WebFetch  {_github_code_search(q)}")
            lines.append("")

        # ── Section 6: Complementary MCP calls ──────────────────────
        lines.append("── COMPLEMENTARY MCP CALLS ──")
        if tech_stack:
            lines.append(f"  map_tech_to_cves(target_domain={target_domain!r}, tech={tech_stack!r})")
            for tech in [t.strip() for t in tech_stack.split(",") if t.strip()][:2]:
                lines.append(f"  search_cve(product={tech!r})")
        if kb and v in ("sqli", "xss", "ssrf", "ssti", "rce", "xxe", "open_redirect", "csrf"):
            lines.append(f"  get_payloads(category={v!r})  # crafted payloads with WAF-bypass variants")
        if v in ("ssrf", "ssti", "rce", "sqli", "xxe", "request_smuggling"):
            lines.append(f"  auto_probe(endpoint={endpoint!r}, parameter='PARAM', categories=[{v!r}])")
        if v == "race_condition":
            lines.append(f"  test_race_condition(url={endpoint!r}, ...)")
        if v == "websocket":
            lines.append(f"  test_websocket(url={endpoint!r}, ...)")
        if v == "ssti":
            lines.append(f"  test_ssti(endpoint={endpoint!r}, parameter='PARAM')")
        if v == "prototype_pollution":
            lines.append(f"  test_prototype_pollution(url={endpoint!r}, ...)")
        if v == "xxe":
            lines.append(f"  test_xxe(url={endpoint!r}, ...)")
        if v == "csrf":
            lines.append(f"  test_csrf(url={endpoint!r}, ...)")
        if v == "ssrf":
            lines.append(f"  test_ssrf(url={endpoint!r}, ...)")
        lines.append("")

        # ── Section 7: Triage protocol ──────────────────────────────
        lines.append("── TRIAGE PROTOCOL ──")
        lines.append("  1. Read DEEP-DIVE + OBSCURE inline (free, no fetch). Pick ONE you haven't tested.")
        lines.append("  2. WebFetch the PortSwigger Academy + HackTricks links — class methodology.")
        lines.append("  3. Run 2-3 WebSearch queries — disclosed-report priors + tech-specific bypass.")
        lines.append("  4. WebFetch 1-2 advisory DBs (Exploit-DB / OSV / Snyk DB) when tech_stack supplied.")
        lines.append("  5. Form ONE testable hypothesis. Probe via MCP through Burp (Rule 26a).")
        lines.append("  6. PASS → assess_finding + chain via CHAIN HYPOTHESES. FAIL → cycle once, then router.")
        lines.append("  Budget: ≤6 web hits per research cycle. Over-research is the failure mode.")

        return "\n".join(lines)
