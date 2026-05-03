"""Shared constants for the scan engine. No imports beyond pathlib."""

from pathlib import Path


KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"


# Reference-only files — auto_probe skips these. Reasons inline so additions
# / removals get reviewed.
#   tech_vulns           — pure CVE knowledge, no probes
#   race_condition       — covered by dedicated test_race_condition tool
#   request_smuggling    — needs per-request sequence tracking; auto_probe is single-shot
#   clickjacking         — needs browser context (frame-busting tests)
#   insecure_randomness  — needs N-sample statistical analysis
#   source_code_exposure — covered by discover_common_files
#   xs_leak              — needs browser-side timing
#   captcha_bypass       — human-driven verification
#   csv_injection        — payload via export, not request
#   dependency_confusion — registry side-channel, not target HTTP
#   web_cache_deception  — path manipulation, not parameter fuzzing
#   web_cache_poisoning_dos — DoS-class; out of safety scope per Rule 5
# NOTE: file_upload was previously here; removed in v0.5.
_REFERENCE_ONLY = {
    "tech_vulns", "race_condition", "request_smuggling", "clickjacking",
    "web_cache_deception", "insecure_randomness", "source_code_exposure",
    "csv_injection", "dependency_confusion", "xs_leak",
    "web_cache_poisoning_dos", "captcha_bypass", "http3_quic",
}

# Parameter name → vulnerability classification (used by attack-priority routing)
_PARAM_RISK_MAP = {
    "sqli_idor": ["id", "uid", "pid", "user_id", "account_id", "order_id", "item_id", "product_id", "num", "page",
                   "profile_id", "doc_id", "invoice_id", "ticket_id", "org_id", "workspace_id", "project_id"],
    "xss_sqli": ["search", "q", "query", "keyword", "name", "comment", "message", "text", "content",
                  "title", "description", "bio", "note", "subject", "body", "input", "value", "label"],
    "redirect_ssrf": ["url", "redirect", "next", "return", "goto", "dest", "callback", "uri", "link", "href", "forward",
                       "continue", "redir", "return_url", "redirect_uri", "target", "site", "feed", "webhook", "proxy"],
    "lfi": ["file", "path", "dir", "page", "include", "template", "load", "read", "doc", "download",
            "filepath", "filename", "folder", "document", "src", "source"],
    "cmdi": ["cmd", "command", "exec", "run", "ping", "ip", "hostname", "address", "host", "port", "domain"],
    "ssti": ["template", "render", "view", "layout", "preview", "expression", "eval", "format", "output", "display"],
    "upload": ["upload", "attachment", "image", "photo", "avatar", "import", "media", "csv", "document"],
    "deserialization": ["data", "object", "serialized", "viewstate", "state", "payload"],
    "nosql": ["filter", "where", "populate", "select", "aggregate", "lookup", "match", "expr"],
    "xxe": ["xml", "soap", "wsdl", "feed", "rss", "svg", "content_type", "envelope", "dtd"],
    "jwt_auth": ["token", "jwt", "access_token", "id_token", "refresh_token", "bearer", "api_key", "apikey", "secret"],
    "mass_assignment": ["role", "admin", "is_admin", "privilege", "permission", "group", "level", "verified",
                         "active", "approved", "is_staff", "is_superuser", "credits", "balance", "plan"],
    "graphql": ["query", "mutation", "variables", "operationname", "operationName", "graphql"],
    "prototype_pollution": ["__proto__", "constructor", "prototype", "merge", "extend", "clone", "deep"],
    "idor_uuid": ["uuid", "guid", "ref", "slug", "handle", "hash", "resource_id", "object_id", "entity_id"],
    "oauth": ["code", "state", "redirect_uri", "code_verifier", "code_challenge", "nonce", "client_id"],
    "cache_key": ["cb", "cachebuster", "utm_source", "utm_content", "utm_campaign", "fbclid", "gclid"],
    "saml": ["SAMLResponse", "SAMLRequest", "RelayState", "saml_token", "assertion"],
    "authentication": ["otp", "mfa_code", "totp", "verification_code", "2fa", "reset_token", "remember_me"],
    "business_logic": ["price", "amount", "total", "cost", "quantity", "qty", "discount", "coupon", "step", "stage"],
    "web_llm": ["message", "prompt", "instruction", "chat", "query", "question", "context", "system_prompt"],
    "host_header": ["host", "x_forwarded_host", "x_forwarded_for"],
    "second_order": ["name", "username", "email", "title", "description", "comment", "bio", "feedback"],
    "ldap_injection": ["username", "user", "login", "uid", "cn", "dn", "search", "filter", "ldap", "query"],
    "xpath_injection": ["xpath", "path", "node", "xml", "search", "query", "filter"],
    "ssi_injection": ["name", "title", "comment", "message", "text", "input"],
    "xslt_injection": ["xsl", "xslt", "transform", "stylesheet", "xml", "template"],
    "css_injection": ["style", "css", "color", "background", "theme", "class"],
}

# Hidden-parameter wordlist (~200 entries). Vendor-aware: Shopify, Magento, SAP,
# Sitecore, Salesforce, AWS, Atlassian, plus modern API frameworks.
_COMMON_PARAMS = [
    # Identifiers
    "id", "uid", "pid", "sid", "tid", "cid", "oid", "bid", "fid", "rid",
    "user_id", "userid", "account_id", "order_id", "item_id", "product_id",
    "post_id", "comment_id", "doc_id", "ref_id", "guid", "uuid", "ulid",
    # Pagination / sort
    "page", "page_size", "per_page", "limit", "offset", "size", "from", "to",
    "skip", "take", "cursor", "after", "before", "sort", "order", "order_by",
    "direction", "asc", "desc",
    # Search / filter
    "search", "q", "query", "keyword", "term", "filter", "where", "match",
    "category", "tag", "type", "subtype", "status", "state", "kind",
    # User / auth
    "name", "email", "user", "username", "login", "password", "passwd",
    "token", "access_token", "id_token", "refresh_token", "key", "api_key",
    "apikey", "secret", "auth", "session", "csrf", "xsrf", "code", "nonce",
    "state", "client_id", "client_secret",
    # Redirects / URLs
    "redirect", "url", "next", "return", "callback", "callback_url",
    "redirect_uri", "return_url", "return_to", "continue", "goto", "dest",
    "destination", "redir", "forward", "target", "uri", "site",
    # Files / paths
    "file", "filename", "path", "filepath", "dir", "folder", "include",
    "template", "view", "page", "load", "read", "doc", "download", "src",
    "source", "import", "export",
    # Commands / actions
    "action", "do", "method", "func", "function", "cmd", "command", "exec",
    "run", "ping", "ip", "hostname", "host", "address", "port", "domain",
    # Format / locale
    "format", "fmt", "output", "type", "ext", "extension", "lang", "locale",
    "language", "country", "region", "timezone", "tz",
    # Debug / config
    "debug", "verbose", "trace", "log", "test", "preview", "draft",
    "force", "confirm", "skip", "ignore", "bypass", "config", "setting",
    "env", "mode", "level", "phase", "step", "stage",
    # Privilege / role
    "admin", "role", "permission", "privilege", "scope", "group",
    # Generic
    "input", "output", "data", "value", "v", "version", "ver", "rev",
    "checksum", "hash", "sig", "signature", "ts", "timestamp", "time",
]

_EXTENDED_PARAMS = _COMMON_PARAMS + [
    # Resource identifiers
    "account", "profile", "invoice_id", "ticket_id", "org_id", "workspace_id",
    "project_id", "team_id", "tenant_id", "channel_id", "thread_id",
    "message_id", "notification_id", "task_id", "report_id", "asset_id",
    "object_id", "entity_id", "resource_id", "node_id", "edge_id",
    # Auth / OAuth / OIDC
    "code_verifier", "code_challenge", "code_challenge_method",
    "grant_type", "response_type", "response_mode", "prompt", "max_age",
    "id_token_hint", "login_hint", "ui_locales", "acr_values",
    "audience", "issuer", "subject_token", "actor_token",
    # API / GraphQL
    "query", "mutation", "subscription", "operationName", "variables",
    "extensions", "persistedQuery", "fields", "include", "exclude",
    "expand", "embed", "relations", "with", "select", "populate",
    "projection", "aggregate", "lookup", "match", "expr", "pipeline",
    "sparse", "fieldset",
    # Business logic / payments
    "checkout", "payment", "amount", "price", "subtotal", "total", "cost",
    "quantity", "qty", "coupon", "promo", "discount", "voucher", "credit",
    "balance", "currency", "rate", "tax", "fee", "shipping",
    "address", "shipping_address", "billing_address", "phone", "zip",
    # Networking / infra
    "host", "port", "domain", "subdomain", "endpoint", "resource", "service",
    "cluster", "namespace", "pod", "container", "image", "tag", "branch",
    "environment", "stage",
    # DB / schema
    "field", "column", "table", "database", "schema", "index", "collection",
    "where", "having", "group_by",
    # Network / HTTP
    "method", "verb", "request_id", "trace_id", "span_id", "correlation_id",
    "x_forwarded_for", "x_forwarded_host", "x_real_ip", "x_request_id",
    # Workflow / state
    "timeout", "retry", "ttl", "cache", "refresh", "invalidate",
    "delete", "remove", "update", "create", "edit", "patch", "submit",
    "process", "validate", "verify", "check", "test", "publish",
    "draft", "preview", "schedule", "approve", "reject", "lock", "unlock",
    "activate", "deactivate", "enable", "disable",
    # File ops
    "upload", "download", "fetch", "load", "read", "write", "save", "store",
    "attachment", "image", "photo", "avatar", "media", "csv", "pdf",
    # Deserialization / RPC
    "viewstate", "__VIEWSTATE", "__EVENTVALIDATION", "__EVENTTARGET",
    "data", "object", "serialized", "payload", "body", "envelope",
    # Mass-assignment honeypots
    "is_admin", "is_staff", "is_superuser", "is_verified", "is_active",
    "is_approved", "is_premium", "is_paid", "verified", "active", "approved",
    "credits", "tokens", "coins", "points", "score", "level", "tier", "plan",
    "subscription", "membership",
    # Vendor / framework specific
    # Shopify
    "shop", "shop_id", "store_id", "myshopify_domain", "collection_id",
    "collections", "variant_id", "metafield_id",
    # Magento
    "store", "store_code", "store_view", "website_id", "customer_id",
    # Sitecore
    "site_id", "site_name", "language_code", "database_name", "item_path",
    # SAP
    "client", "system_id", "logical_system",
    # Salesforce
    "sObject", "sobject_type", "lead_id", "opportunity_id", "case_id",
    "contact_id", "campaign_id",
    # WordPress
    "post_type", "post_status", "taxonomy", "term_id", "meta_key", "meta_value",
    # AWS / cloud
    "region", "availability_zone", "az", "vpc_id", "instance_id", "ami_id",
    "bucket", "object_key", "arn", "role_arn", "principal",
    # Atlassian (Jira/Confluence)
    "issueKey", "issueId", "projectKey", "projectId", "boardId", "sprintId",
    "spaceKey", "pageId",
    # Oracle / banking
    "realm", "schema_name", "principal_id", "lookup_id",
    # Mobile / IAP
    "receipt", "transaction_id", "purchase_token", "subscription_id",
    "device_id", "device_token", "platform",
    # Generic high-yield
    "callback_url", "webhook", "webhook_url", "redirect_url",
    "import_url", "fetch_url", "image_url", "avatar_url", "picture",
    "logo", "thumbnail", "banner",
    # Ratelimit / abuse
    "captcha", "captcha_token", "recaptcha", "hcaptcha", "turnstile",
    "puzzle", "challenge",
    # SAML / SSO
    "SAMLResponse", "SAMLRequest", "RelayState", "saml_token", "assertion",
    "idp", "sp", "binding", "destination", "issuer",
    # Misc
    "preview", "draft", "snapshot", "history", "version_id", "rev_id",
    "compare", "diff", "merge", "branch", "tag",
]
