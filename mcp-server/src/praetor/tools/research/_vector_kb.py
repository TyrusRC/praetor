"""Class-specific deep-dive prompts.

Each entry: deep_dive (open-ended exploration questions), obscure
(vectors operators commonly miss), chain (what the bug enables).
"""

from __future__ import annotations


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


