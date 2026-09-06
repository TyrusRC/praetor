"""Injection & server-side-reach class deep-dive prompts (sqli/xss/ssrf/ssti/idor/rce).

Data slice re-assembled by _vector_kb.py — do not import directly.
"""

from __future__ import annotations


_INJECTION: dict[str, dict[str, list[str]]] = {
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
}
