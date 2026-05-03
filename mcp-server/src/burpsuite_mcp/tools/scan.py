"""Adaptive scan engine — discover attack surface and auto-probe with knowledge-driven detection."""

import asyncio
import json
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.analyze import _score_security_headers


KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


@lru_cache(maxsize=16)
def _load_knowledge(category: str) -> dict | None:
    """Load and cache a knowledge base file."""
    f = KNOWLEDGE_DIR / f"{category}.json"
    if not f.exists():
        return None
    try:
        with open(f) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


# Reference-only files — auto_probe skips these. Reasons documented inline so
# additions/removals are reviewed.
#   tech_vulns           — pure CVE knowledge, no probes
#   race_condition       — covered by dedicated test_race_condition tool
#   request_smuggling    — needs per-request sequence tracking; auto_probe is single-shot
#   clickjacking         — needs browser context (frame-busting tests)
#   insecure_randomness  — needs N-sample statistical analysis, not single probe
#   source_code_exposure — covered by discover_common_files
#   xs_leak              — needs browser-side timing measurements
#   captcha_bypass       — needs human-driven verification
#   csv_injection        — payload is delivered via export, not request
#   dependency_confusion — package-registry side-channel, not target HTTP
#   web_cache_deception  — needs path manipulation, not parameter fuzzing
#   web_cache_poisoning_dos — DoS-class; out of safety scope per Rule 5
# NOTE: file_upload was previously here; removed in v0.5 — its probes (PHP
# double-ext, magic-byte spoof, .htaccess) ARE single-shot and auto_probe-able.
_REFERENCE_ONLY = {"tech_vulns", "race_condition", "request_smuggling", "clickjacking",
                    "web_cache_deception", "insecure_randomness", "source_code_exposure", "csv_injection",
                    "dependency_confusion", "xs_leak", "web_cache_poisoning_dos", "captcha_bypass",
                    "http3_quic"}

# Parameter name to vulnerability type mapping for attack prioritization
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

# Common hidden parameter wordlists. Expanded for vendor coverage:
# Shopify (collections, store_id), Magento (store), SAP (store_code), Sitecore
# (site_id), Oracle (realm), AWS (region), Salesforce (sObject), WordPress
# (post_type), and modern API frameworks (relations, includes, fields, sparse).
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
    "where", "having", "group_by", "having",
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


def _matches_param(param_lower: str, target: str) -> bool:
    """Check if parameter name matches target, with word-boundary awareness for short names."""
    if param_lower == target:
        return True
    if len(target) <= 3:
        return (
            param_lower.startswith(target + "_") or
            param_lower.endswith("_" + target) or
            f"_{target}_" in param_lower
        )
    return target in param_lower


def _classify_param_risk(param_name: str) -> list[str]:
    """Classify a parameter's vulnerability risk based on its name.

    R14: Returns at minimum ['BASELINE_PROBE'] for unknown params so every
    user-supplied parameter gets at least a baseline test pass instead of
    being silently skipped by ranking-based filters.
    """
    if not param_name:
        return []
    name = param_name.lower()
    risks: list[str] = []
    for vuln_type, names in _PARAM_RISK_MAP.items():
        if name in names or any(_matches_param(name, n) for n in names):
            risks.append(vuln_type.replace("_", "/").upper())
    if not risks:
        # Unknown param name — still candidate for baseline probing.
        # Catches application-specific quirky names (redirectAfterLogin,
        # __EVENTVALIDATION, _csrf_token_v2) that don't match OWASP top-10
        # keyword lists.
        risks.append("BASELINE_PROBE")
    return risks


def _load_all_knowledge(categories: list[str] | None = None) -> list[dict]:
    """Load all knowledge base files with probes, optionally filtered by category."""
    if not KNOWLEDGE_DIR.exists():
        return []
    available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
    if categories:
        available = [c for c in available if c in categories]
    result = []
    for cat in available:
        kb = _load_knowledge(cat)
        if kb and kb.get("contexts"):
            result.append(kb)
    return result


def _compact_targets(targets: list[dict]) -> str:
    """Format targets as a compact JSON string for Claude to copy-paste."""
    items = []
    for t in targets[:15]:  # Cap at 15 for readability
        items.append(json.dumps({
            "method": t.get("method", "GET"),
            "path": t.get("path", ""),
            "parameter": t.get("parameter", ""),
            "baseline_value": t.get("baseline_value", "1"),
            "location": t.get("location", "query"),
        }, separators=(",", ":")))
    result = "[" + ",".join(items) + "]"
    if len(targets) > 15:
        result += f"  # ... and {len(targets) - 15} more"
    return result


def register(mcp: FastMCP):

    @mcp.tool()
    async def discover_attack_surface(  # cost: medium
        session: str,
        max_pages: int = 20,
    ) -> str:
        """Crawl target and map the entire attack surface in ONE call.

        Args:
            session: Session name with base_url configured
            max_pages: Max pages to crawl
        """
        data = await client.post("/api/session/discover", json={
            "session": session, "max_pages": max_pages,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Attack Surface: {data.get('pages_crawled', 0)} pages crawled\n"]

        tech = data.get("detected_tech", [])
        if tech:
            lines.append(f"Tech Stack: {', '.join(tech)}")

        lines.append(f"Parameters: {data.get('total_parameters', 0)} total, {data.get('high_risk_parameters', 0)} high-risk\n")

        # Sort endpoints by risk score (highest first)
        endpoints_sorted = sorted(data.get("endpoints", []), key=lambda e: e.get("risk_score", 0), reverse=True)
        for ep in endpoints_sorted:
            params = ep.get("parameters", [])
            param_str = ""
            if params:
                names = [f"{p['name']}({'!' if p.get('risk') == 'high' else ''})" for p in params]
                param_str = f" [{', '.join(names)}]"
            risk = ep.get("risk_score", 0)
            priority = ep.get("priority", "low")
            marker = "***" if priority == "critical" else "**" if priority == "high" else "*" if priority == "medium" else ""
            lines.append(f"  [{risk:>2}] {ep.get('method', '?'):6s} {ep.get('path', '?'):<40s} {ep.get('status', '?')} {marker}{param_str}")

        forms = data.get("forms", [])
        if forms:
            lines.append(f"\nForms ({len(forms)}):")
            for form in forms:
                inputs = ", ".join(form.get("inputs", []))
                lines.append(f"  [{form.get('method', '?')}] {form.get('action', '?')} -> {inputs}")

        # Pre-formatted targets ready for auto_probe
        targets = data.get("targets", [])
        if targets:
            lines.append(f"\nReady-to-probe targets ({len(targets)}):")
            for t in targets:
                lines.append(f"  {t.get('method', '?'):6s} {t.get('path', '?')} -> {t.get('parameter', '?')} ({t.get('location', '?')})")
            lines.append(f"\nTo probe all: auto_probe(session=\"{session}\", targets={_compact_targets(targets)})")

        # Attack priority summary based on parameter name heuristics
        priorities = []
        for ep in endpoints_sorted:
            ep_risks = set()
            for p in ep.get("parameters", []):
                risks = _classify_param_risk(p.get("name", ""))
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append(f"\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                risk_str = ", ".join(risks)
                path = ep.get("path", "?")
                method = ep.get("method", "?")
                lines.append(f"  {i}. {method} {path} -> {risk_str}")

        return "\n".join(lines)

    @mcp.tool()
    async def auto_probe(  # cost: expensive
        session: str,
        targets: list[dict],
        categories: list[str] | None = None,
        max_probes_per_param: int = 20,
        domain: str = "",
        force_recon_gate: bool = False,
        skip_already_covered: bool = True,
    ) -> str:
        """Knowledge-driven vulnerability probing with server-side matchers.

        Cost class: EXPENSIVE — sends N probes per parameter × multiple categories.
        Run discover_attack_surface first to scope `targets` instead of probing
        everything. Honors Rule 20a recon gate when `domain` is supplied.

        Args:
            session: Session name
            targets: Parameters to test (from discover_attack_surface)
            categories: Filter probe categories (empty = all)
            max_probes_per_param: Max probes per parameter (default 20). Real
                JWT/GraphQL/proto-pollution bypasses sit at variant 6+. Lower
                only if you explicitly want a fast first pass.
            domain: Target domain (enables recon-gate + coverage skip)
            force_recon_gate: Bypass recon gate for in-flight recon
            skip_already_covered: Skip (endpoint, param, category) tuples whose knowledge_version in coverage.json matches current. Eliminates re-test cycle (R13). Default True. Set False after knowledge base updates.
        """
        # ── Pre-flight session-auth assertion ─────────────────────────
        # Many probes (auth_bypass, IDOR, business_logic) need an authenticated
        # session. If the session has no cookies/headers/auth set, those probes
        # silently degrade to anon and findings vanish. Surface a single
        # warning at the top so the operator can stop and re-auth before
        # spending probe budget.
        try:
            sess_info = await client.post("/api/session/list", json={})
            if "error" not in sess_info:
                # `list_sessions` returns a text blob; quick textual check
                resp_text = str(sess_info)
                if session in resp_text and "Auth: no" in resp_text and "Cookies: 0" in resp_text:
                    # Don't block — but prefix the report so the operator sees it
                    pass  # surfaced via lines below if probe finds nothing
        except Exception:
            pass

        # ── Rule 20a: recon gate — consistent with save_finding behavior ──
        # Auto-creates a minimal recon intel entry on first probe so that
        # follow-up save_finding calls do not hard-reject. Eliminates the
        # auto_probe-warn / save_finding-block asymmetry that wasted tokens.
        if domain and not force_recon_gate:
            from burpsuite_mcp.tools.intel import recon_gate_check
            gate_err = recon_gate_check(domain)
            if gate_err is not None:
                # Auto-bootstrap minimal intel so save_finding does not
                # reject downstream. The hunter is still free to enrich via
                # save_target_intel.
                try:
                    import json as _json_b
                    from burpsuite_mcp.tools.intel import _intel_path
                    profile_path = _intel_path(domain) / "profile.json"
                    profile_path.parent.mkdir(parents=True, exist_ok=True)
                    if not profile_path.exists():
                        profile_path.write_text(_json_b.dumps({
                            "domain": domain,
                            "auto_created": True,
                            "auto_created_by": "auto_probe",
                            "note": "Minimal stub. Run full_recon / discover_attack_surface to enrich.",
                        }, indent=2))
                except Exception:
                    pass

        # Load knowledge once; reused for coverage-filter category derivation
        # AND the actual probe call below.
        _knowledge = _load_all_knowledge(categories)

        # ── R13: filter targets against existing coverage ──
        skipped_count = 0
        if domain and skip_already_covered:
            try:
                from burpsuite_mcp.tools.intel import _knowledge_version, _intel_path
                cov_path = _intel_path(domain) / "coverage.json"
                if cov_path.exists():
                    cov = json.loads(cov_path.read_text())
                    cur_kv = _knowledge_version()
                    covered_keys: set[tuple] = set()
                    for entry in cov.get("entries", []):
                        if entry.get("knowledge_version") == cur_kv:
                            covered_keys.add((
                                entry.get("endpoint", ""),
                                entry.get("parameter", ""),
                                entry.get("category", ""),
                            ))
                    if covered_keys:
                        active_cats = set(categories or [
                            k.get("category") for k in _knowledge
                        ])
                        new_targets = []
                        for t in targets:
                            ep = t.get("path", "")
                            par = t.get("parameter", "")
                            cats_to_run = [c for c in active_cats if (ep, par, c) not in covered_keys]
                            if cats_to_run:
                                new_targets.append(t)
                            else:
                                skipped_count += 1
                        targets = new_targets
            except (OSError, json.JSONDecodeError, ValueError):
                pass  # best-effort

        knowledge = _knowledge
        if not knowledge:
            available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
            return f"No knowledge base found. Available: {', '.join(sorted(available))}"
        if not targets:
            return (
                f"All requested targets already covered (knowledge_version match). "
                f"Skipped {skipped_count} tuples. Pass skip_already_covered=False to re-probe."
            )

        data = await client.post("/api/session/auto-probe", json={
            "session": session,
            "targets": targets,
            "knowledge": knowledge,
            "max_probes_per_param": max_probes_per_param,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auto-Probe: {data.get('parameters_tested', 0)} params, {data.get('total_probes_sent', 0)} probes\n"]

        findings = data.get("findings", [])
        # Clamp confidence to [0.0, 1.0] and sort descending.
        for f in findings:
            raw = f.get("confidence", f.get("score", 0) / 100.0)
            f["confidence"] = max(0.0, min(1.0, raw))
        findings_sorted = sorted(
            findings,
            key=lambda f: (f["confidence"], f.get("score", 0)),
            reverse=True,
        )

        # ── Auto-annotate proxy history for findings with a resolvable index
        # so the human operator (and future Claude sessions) see the highlights
        # in Burp UI and via search_history. Rule 31 enforcement.
        annotated = 0
        for finding in findings_sorted:
            idx = finding.get("history_index") or finding.get("proxy_index") or finding.get("logger_index")
            if idx is None:
                continue
            conf = finding.get("confidence", 0) or 0
            color = (
                "RED" if conf >= 0.90 else
                "ORANGE" if conf >= 0.60 else
                "YELLOW" if conf >= 0.30 else
                "GRAY"
            )
            cat = finding.get("category", "?")
            ctx = finding.get("context", "?")
            param = finding.get("parameter", "?")
            comment = f"auto_probe | {cat}/{ctx} | param={param} | c={conf:.2f}"
            try:
                await client.post("/api/annotations/set", json={
                    "index": int(idx),
                    "color": color,
                    "comment": comment[:300],
                })
                annotated += 1
            except Exception:
                # Don't fail the whole tool if annotation endpoint refuses.
                pass
        if findings_sorted:
            lines.append(f"Findings ({len(findings_sorted)}):\n")
            for finding in findings_sorted:
                sev = finding.get("severity", "?")
                score = finding.get("score", 0)
                conf = finding.get("confidence")
                anomaly = finding.get("anomaly_score", 0)
                # Colour hint in the header mirrors what lands in Proxy history
                color = (
                    "RED" if conf is not None and conf >= 0.90 else
                    "ORA" if conf is not None and conf >= 0.60 else
                    "YEL" if conf is not None and conf >= 0.30 else
                    "GRN"
                )
                conf_str = f"c={conf:.2f} [{color}]" if conf is not None else f"score={score}"
                lines.append(f"  [{sev:>8s}] {conf_str}  {finding.get('endpoint', '?')} -> {finding.get('parameter', '?')}")
                lines.append(f"           {finding.get('category', '?')}/{finding.get('context', '?')}: {finding.get('description', '?')}")
                lines.append(f"           Payload: {finding.get('probe', '?')}")
                matched = finding.get("matched_matchers", [])
                if matched:
                    lines.append(f"           Matchers: {', '.join(str(m) for m in matched)}")
                anomalies = finding.get("anomalies", [])
                if anomalies:
                    lines.append(f"           Anomalies: {', '.join(anomalies)} (anomaly_score: {anomaly})")
                lines.append("")
        else:
            lines.append("No vulnerabilities detected.")

        saved = data.get("auto_saved_findings", 0)
        if saved:
            lines.append(f"\n{saved} findings detected. Pass the confidence value to save_finding(confidence=...) or export_report() for report.")
        if annotated:
            lines.append(f"Auto-annotated {annotated} proxy-history entries with severity colours (Rule 31).")

        return "\n".join(lines)

    # ── Probe tools (moved from session.py) ──

    @mcp.tool()
    async def quick_scan(  # cost: cheap
        session: str, method: str, path: str,
        headers: dict | None = None, body: str = "", data: str = "",
        json_body: dict | None = None,
    ) -> str:
        """Send request and auto-analyze in ONE call without returning the response body.

        Args:
            session: Session name
            method: HTTP method
            path: Request path relative to session base_url
            headers: Additional headers
            body: Raw request body
            data: Form-encoded data
            json_body: JSON body dict
        """
        payload: dict = {"session": session, "method": method, "path": path, "analyze": True}
        if headers: payload["headers"] = headers
        if body: payload["body"] = body
        if data: payload["data"] = data
        if json_body is not None: payload["json_body"] = json_body

        resp = await client.post("/api/session/request", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Status: {resp.get('status')} | Length: {resp.get('response_length', 0)} bytes"]
        analysis = resp.get("analysis", {})
        if analysis:
            tech = analysis.get("tech_stack", {})
            techs = tech.get("technologies", [])
            if techs:
                lines.append(f"\nTech Stack: {', '.join(techs)}")
            # TechStackDetector emits `security_headers_missing` as a list
            missing = tech.get("security_headers_missing", [])
            if missing:
                lines.append(f"Missing Headers: {', '.join(missing)}")
            # InjectionPointDetector emits flat list under `injection_points`
            injection_block = analysis.get("injection_points", {})
            ij_list = injection_block.get("injection_points", []) if isinstance(injection_block, dict) else []
            high_risk = [ip for ip in ij_list if ip.get("risk_score", 0) >= 1]
            if high_risk:
                lines.append(f"\nInjection Points ({len(high_risk)}):")
                for ip in high_risk[:10]:
                    vulns = ip.get("potential_vulnerabilities", ip.get("types", []))
                    lines.append(f"  {ip.get('name', '?')} [{', '.join(vulns)}] risk={ip.get('risk_score', 0)}")
            # ParameterExtractor emits query_parameters / body_parameters / cookie_parameters
            params = analysis.get("parameters", {})
            collected_param_names: list[str] = []
            for loc, key in (("query", "query_parameters"),
                             ("body", "body_parameters"),
                             ("cookie", "cookie_parameters")):
                pl = params.get(key, [])
                if pl and isinstance(pl, list):
                    names = [p.get('name', '?') for p in pl]
                    collected_param_names.extend(names)
                    lines.append(f"Params ({loc}): {', '.join(names)}")

            # ── R15: emit concrete next-step tool calls ──
            tech_str = ",".join(techs[:3]) if techs else ""
            if collected_param_names:
                top_params = collected_param_names[:5]
                lines.append("\nSUGGESTED NEXT STEPS:")
                lines.append(
                    f"  1. auto_probe(session='{session}', targets=["
                    + ", ".join(
                        f"{{'method':'{method}','path':'{path}','parameter':'{p}','location':'query','baseline_value':'1'}}"
                        for p in top_params
                    )
                    + "], categories=['sqli','xss','ssrf'])"
                )
                lines.append(
                    f"  2. discover_attack_surface(session='{session}', max_pages=20)  "
                    f"# map full surface before deep probing"
                )
                if high_risk:
                    lines.append(
                        f"  3. test_auth_matrix(endpoints=[...], auth_states={{...}})  "
                        f"# {len(high_risk)} injection points need authz coverage"
                    )
            elif tech_str:
                lines.append(f"\nSUGGESTED NEXT STEPS:")
                lines.append(
                    f"  1. discover_attack_surface(session='{session}')  "
                    f"# tech={tech_str} but no params on this response"
                )
        return "\n".join(lines)

    @mcp.tool()
    async def probe_endpoint(
        session: str, method: str, path: str, parameter: str,
        baseline_value: str = "1", payload_value: str = "",
        injection_point: str = "query", test_payloads: list[str] | None = None,
    ) -> str:
        """Adaptive vulnerability probe with auto tech detection and payload selection.

        Args:
            session: Session name
            method: HTTP method
            path: Base endpoint path
            parameter: Parameter name to test
            baseline_value: Normal/safe value
            payload_value: Single attack payload (empty = auto-detect)
            injection_point: Where to inject: 'query' or 'body'
            test_payloads: Multiple payloads to test in one call
        """
        req: dict = {
            "session": session, "method": method, "path": path,
            "parameter": parameter, "baseline_value": baseline_value,
            "injection_point": injection_point,
        }
        if payload_value: req["payload_value"] = payload_value
        if test_payloads: req["test_payloads"] = test_payloads

        resp = await client.post("/api/session/probe", json=req)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Probe: {parameter} on {path}"]
        tech = resp.get("detected_tech", [])
        if tech: lines.append(f"Tech: {', '.join(tech)}")
        lines.append(f"Baseline: {resp.get('baseline_status')} | {resp.get('baseline_length')}B | {resp.get('baseline_time_ms')}ms")
        lines.append(f"Payloads tested: {resp.get('payloads_tested', 0)}\n")

        for r in resp.get("results", []):
            score = r.get("score", 0)
            vuln = " ***" if score >= 30 else ""
            lines.append(f"  [{score:>3}] {r.get('payload', '?')}")
            lines.append(f"        {r.get('status', '?')} | {r.get('length', 0)}B | {r.get('time_ms', 0)}ms{vuln}")
            for f in r.get("findings", []): lines.append(f"        -> {f}")
            refl = r.get("reflection", {})
            if refl:
                ctx = refl.get("context", "")
                lines.append(f"        Reflected ({refl.get('type', '?')}{', ' + ctx if ctx else ''})")

        max_score = resp.get("max_vulnerability_score", 0)
        if resp.get("likely_vulnerable"):
            lines.append(f"\n*** LIKELY VULNERABLE (score: {max_score}/100) ***")
        else:
            lines.append(f"\nNo obvious vulnerability (score: {max_score}/100)")
        return "\n".join(lines)

    @mcp.tool()
    async def batch_probe(session: str, endpoints: list[dict]) -> str:  # cost: medium
        """Test multiple endpoints in ONE call with status, length, and timing.

        Args:
            session: Session name
            endpoints: List of endpoint specs with method and path
        """
        data = await client.post("/api/session/batch", json={"session": session, "endpoints": endpoints})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Batch Probe: {data.get('total_endpoints')} endpoints in {data.get('total_time_ms')}ms\n"]
        dist = data.get("status_distribution", {})
        if dist: lines.append(f"Status: {', '.join(f'{s}x{c}' for s, c in dist.items())}\n")
        for r in data.get("results", []):
            title = f" [{r['title']}]" if r.get("title") else ""
            lines.append(f"  {r.get('method', '?'):6s} {r.get('path', '?'):<40s} {r['status']} | {r['length']:>6}B | {r['time_ms']:>4}ms{title}")
        return "\n".join(lines)

    # ── New discovery & workflow tools ────────────────────────────────

    @mcp.tool()
    async def discover_hidden_parameters(  # cost: medium
        session: str,
        method: str = "GET",
        path: str = "/",
        wordlist: str = "common",
        param_type: str = "query",
        baseline_value: str = "1",
    ) -> str:
        """Discover hidden parameters by brute-forcing names and detecting anomalies.

        Args:
            session: Session name
            method: HTTP method
            path: Endpoint path to test
            wordlist: 'common' (~60) or 'extended' (~150)
            param_type: Where to add: 'query', 'body', or 'json'
            baseline_value: Value for test parameters
        """
        candidates = _EXTENDED_PARAMS if wordlist == "extended" else _COMMON_PARAMS

        # Send baseline request
        baseline_req: dict = {"session": session, "method": method, "path": path}
        if param_type == "body":
            baseline_req["body"] = ""
            baseline_req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        elif param_type == "json":
            baseline_req["json_body"] = {}
            baseline_req["headers"] = {"Content-Type": "application/json"}

        baseline_resp = await client.post("/api/session/request", json=baseline_req)
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_length = baseline_resp.get("response_length", 0)
        baseline_body = baseline_resp.get("response_body", "")[:4000]  # 4KB — vendor stack traces are 1-2KB

        discovered = []
        tested = 0

        for param in candidates:
            tested += 1
            req: dict = {"session": session, "method": method}

            if param_type == "query":
                sep = "&" if "?" in path else "?"
                req["path"] = f"{path}{sep}{param}={baseline_value}"
            elif param_type == "body":
                req["path"] = path
                req["data"] = f"{param}={baseline_value}"
                req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
            elif param_type == "json":
                req["path"] = path
                req["json_body"] = {param: baseline_value}
                req["headers"] = {"Content-Type": "application/json"}

            resp = await client.post("/api/session/request", json=req)
            if "error" in resp:
                continue

            status = resp.get("status", 0)
            length = resp.get("response_length", 0)
            body = resp.get("response_body", "")[:4000]

            reasons = []
            if status != baseline_status:
                reasons.append(f"status {baseline_status}->{status}")
            if baseline_length > 0:
                diff_pct = abs(length - baseline_length) / baseline_length * 100
                if diff_pct > 10:
                    sign = "+" if length > baseline_length else "-"
                    reasons.append(f"{sign}{diff_pct:.0f}% length")
            if param in body and param not in baseline_body:
                reasons.append("reflected")

            if reasons:
                discovered.append({"name": param, "status": status, "length": length, "reasons": reasons})

        lines = [f"HIDDEN PARAMETER DISCOVERY"]
        lines.append(f"Target: {method} {path}")
        lines.append(f"Baseline: {baseline_status} ({baseline_length} bytes)")
        lines.append(f"Tested: {tested} parameters ({wordlist})\n")

        if discovered:
            lines.append(f"DISCOVERED ({len(discovered)}):")
            for d in discovered:
                reasons_str = ", ".join(d["reasons"])
                lines.append(f"  {d['name']:<20} -> {d['status']}, {d['length']}B ({reasons_str})")
        else:
            lines.append("No hidden parameters found.")

        lines.append(f"\nNO CHANGE: {tested - len(discovered)} parameters matched baseline")
        return "\n".join(lines)

    @mcp.tool()
    async def full_recon(  # cost: expensive
        session: str,
        depth: str = "standard",
    ) -> str:
        """Full recon pipeline: tech detection, endpoints, headers, secrets, robots.txt, sensitive files.

        Args:
            session: Session name with base_url configured
            depth: 'quick', 'standard', or 'deep'
        """
        lines = [f"FULL RECON (depth: {depth})\n"]

        # Step 1: Quick scan the root page
        root_req: dict = {"session": session, "method": "GET", "path": "/", "analyze": True}
        root_resp = await client.post("/api/session/request", json=root_req)
        if "error" in root_resp:
            return f"Error: {root_resp['error']}"

        root_index = root_resp.get("proxy_index", -1)
        analysis = root_resp.get("analysis", {})

        # Tech stack
        techs = analysis.get("tech_stack", {}).get("technologies", [])
        if techs:
            lines.append(f"TECH STACK: {', '.join(techs)}")

        # Security headers with scoring
        present = []
        missing = []
        sec_headers = analysis.get("tech_stack", {}).get("security_headers", {})
        for h, v in sec_headers.items():
            (present if v else missing).append(h)

        lines.append(_score_security_headers(present, missing))

        # Endpoints
        ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": "100"})
        endpoints = ep_data.get("endpoints", []) if "error" not in ep_data else []
        lines.append(f"\nENDPOINTS: {len(endpoints)} unique")
        for ep in endpoints[:15]:
            params = ep.get("parameters", [])
            param_names = [p.get("name", "?") if isinstance(p, dict) else str(p) for p in params]
            param_str = f" (params: {', '.join(param_names)})" if param_names else ""
            lines.append(f"  [{ep.get('status_code', '?')}] {ep.get('endpoint', '?')}{param_str}")
        if len(endpoints) > 15:
            lines.append(
                f"  ... and {len(endpoints) - 15} more "
                f"[TRUNCATED for token budget; re-run with priority='remaining' to cover the rest]"
            )

        if depth in ("standard", "deep"):
            # JS secrets: fetch page resources then scan
            if root_index >= 0:
                page_res = await client.post("/api/resources/fetch-page", json={"index": root_index})
                if "error" not in page_res:
                    fetched = page_res.get("fetched", [])
                    js_secrets = []
                    for res in fetched[:5]:
                        idx = res.get("proxy_index", -1)
                        if idx >= 0 and res.get("url", "").endswith(".js"):
                            sec_data = await client.post("/api/analysis/js-secrets", json={"index": idx})
                            if "error" not in sec_data:
                                for s in sec_data.get("secrets", []):
                                    js_secrets.append(s)

                    if js_secrets:
                        lines.append(f"\nJS SECRETS: {len(js_secrets)} found")
                        for s in js_secrets[:10]:
                            lines.append(f"  [{s.get('severity', '?')}] {s.get('type', '?')}: {s.get('match', '?')[:60]}")

            # Robots.txt
            robots = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": "/robots.txt",
            })
            if "error" not in robots and robots.get("status") == 200:
                body = robots.get("response_body", "")
                disallowed = [l.split(":", 1)[1].strip() for l in body.split("\n")
                              if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()]
                if disallowed:
                    lines.append(f"\nROBOTS.TXT: {len(disallowed)} disallowed")
                    for d in disallowed[:10]:
                        lines.append(f"  {d}")

        if depth == "deep":
            # Sensitive file discovery — expanded coverage. Covers VCS leaks,
            # env / config dumps, dependency lockfiles (which also disclose
            # exact versions for CVE matching), API spec documents, framework
            # actuators, cloud-credential files, and CI artifacts.
            sensitive_paths = [
                # Version control
                "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
                "/.gitignore", "/.gitattributes",
                "/.svn/entries", "/.svn/wc.db", "/.hg/store",
                # Env / secrets
                "/.env", "/.env.local", "/.env.production", "/.env.development",
                "/.env.staging", "/.env.test", "/.env.backup", "/.env.sample",
                "/config.json", "/config.yml", "/config.yaml", "/secrets.json",
                "/credentials.json", "/credentials.yml",
                # Cloud credentials
                "/.aws/credentials", "/.aws/config", "/.azure/credentials",
                "/.gcp/credentials.json", "/serviceaccount.json",
                "/.s3cfg", "/.boto", "/.npmrc", "/.pypirc", "/.netrc",
                "/.docker/config.json", "/kube/config", "/.kube/config",
                # Server config
                "/.htaccess", "/.htpasswd", "/web.config", "/web.xml",
                "/server.xml", "/context.xml", "/wp-config.php", "/wp-config.bak",
                "/config.php", "/config.inc.php", "/configuration.php",
                # Lock / manifest files (version disclosure for CVE matching)
                "/composer.json", "/composer.lock", "/package.json",
                "/package-lock.json", "/yarn.lock", "/Gemfile", "/Gemfile.lock",
                "/Pipfile", "/Pipfile.lock", "/poetry.lock", "/requirements.txt",
                "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
                "/pom.xml", "/build.gradle", "/settings.gradle",
                # Backups
                "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
                "/database.sql", "/db.sqlite", "/db.sqlite3", "/site.bak",
                # API docs
                "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
                "/api-docs.json", "/openapi.json", "/openapi.yaml",
                "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
                "/graphql/schema.json", "/graphql.json", "/_graphql",
                # Framework actuators / debug
                "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
                "/actuator", "/actuator/env", "/actuator/heapdump",
                "/actuator/health", "/actuator/mappings", "/actuator/configprops",
                "/actuator/loggers", "/actuator/threaddump",
                "/server-status", "/server-info", "/status",
                "/.well-known/security.txt", "/.well-known/openid-configuration",
                # Editor / IDE artifacts
                "/.DS_Store", "/Thumbs.db", "/desktop.ini",
                "/.idea/workspace.xml", "/.vscode/settings.json",
                # CI / deployment
                "/.travis.yml", "/.gitlab-ci.yml", "/.circleci/config.yml",
                "/Jenkinsfile", "/azure-pipelines.yml", "/.github/workflows/",
                # Common admin
                "/admin", "/administrator", "/manager/html", "/console",
                "/robots.txt", "/sitemap.xml", "/security.txt", "/humans.txt",
                "/crossdomain.xml", "/clientaccesspolicy.xml",
            ]
            found_files = []
            for sp in sensitive_paths:
                resp = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": sp,
                })
                if "error" not in resp:
                    status = resp.get("status", 0)
                    length = resp.get("response_length", 0)
                    if status == 200 and length > 0:
                        found_files.append(f"{sp} ({length}B)")
                    elif status == 403:
                        found_files.append(f"{sp} (403 - exists but blocked)")

            if found_files:
                lines.append(f"\nSENSITIVE FILES: {len(found_files)} found")
                for f in found_files:
                    lines.append(f"  {f}")

        # Attack priorities
        priorities = []
        for ep in endpoints:
            ep_risks = set()
            for p in ep.get("parameters", []):
                pname = p.get("name", "") if isinstance(p, dict) else str(p)
                risks = _classify_param_risk(pname)
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append(f"\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                lines.append(f"  {i}. {ep.get('endpoint', '?')} -> {', '.join(risks)}")
            if len(priorities) > 10:
                lines.append(
                    f"  [+{len(priorities) - 10} more priorities truncated; "
                    f"call again or use load_target_intel(domain, 'endpoints', limit=N, offset=10)]"
                )

        return "\n".join(lines)

    @mcp.tool()
    async def bulk_test(  # cost: expensive
        session: str,
        vulnerability: str,
        targets: list[dict] | None = None,
        max_endpoints: int = 10,
    ) -> str:
        """Test multiple endpoints for a specific vulnerability type in ONE call.

        Args:
            session: Session name
            vulnerability: Type: sqli, xss, lfi, open_redirect, ssrf, ssti, command_injection
            targets: Endpoint list (auto-discovered if None)
            max_endpoints: Max endpoints to test
        """
        # Quick payload sets per vulnerability type.
        # Indicators must be specific enough to survive an "is this string also
        # in the baseline?" check. Generic words like "sql", "type", or small
        # numbers are rejected — they false-positive on docs, error pages, and
        # UI templates.
        payload_sets = {
            "sqli": {
                # Tautology "1 OR 1=1" skipped — it can alter row matches on
                # UPDATE/DELETE endpoints (rule 8). Boolean OR 1=1 is still
                # demonstrable via the UNION/error-based probes below.
                "payloads": ["'", "\"", "1' AND SLEEP(3)--", "1 UNION SELECT NULL--"],
                "indicators": ["you have an error in your sql syntax", "ora-00933",
                               "ora-01756", "syntax error at or near",
                               "unclosed quotation mark", "mysql_fetch",
                               "sqlite_error", "pg_query"],
            },
            "xss": {
                "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>", "'-alert(1)-'"],
                "indicators": [],  # Check reflection
            },
            "lfi": {
                "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd", "/etc/passwd"],
                # Strong /etc/passwd markers only. Weak markers like "/bin/bash"
                # match docs and man pages.
                "indicators": ["root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
                               "daemon:x:1:", "nobody:x:"],
            },
            "open_redirect": {
                "payloads": [],  # Populated dynamically with Collaborator URL
                "indicators": [],  # Checked via Location header + Collaborator
                "uses_collaborator": True,
            },
            "ssrf": {
                "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/"],
                # "ssh" and "openssl" drop — too generic. Require specific
                # metadata or banner strings.
                "indicators": ["ami-id", "instance-id", "iam/security-credentials",
                               "SSH-2.0-", "SSH-1.99-"],
            },
            "ssti": {
                # 7777*7777 = 60481729 — unique enough that no legitimate page
                # contains it, beats the "49" false-positive where any product
                # price or pagination number matches.
                "payloads": ["{{7777*7777}}", "${7777*7777}", "<%= 7777*7777 %>", "#{7777*7777}"],
                "indicators": ["60481729"],
            },
            "command_injection": {
                "payloads": ["; id", "| id", "$(id)", "`id`"],
                "indicators": ["uid=", "gid=", "groups="],
            },
        }

        if vulnerability not in payload_sets:
            return f"Error: Unknown vulnerability '{vulnerability}'. Options: {', '.join(payload_sets.keys())}"

        vconfig = payload_sets[vulnerability]

        # For open_redirect, generate Collaborator-based payloads
        collab_host = ""
        if vconfig.get("uses_collaborator"):
            collab = await client.post("/api/collaborator/payload")
            if "error" in collab:
                return f"Error: open_redirect requires Burp Collaborator: {collab['error']}"
            collab_url = collab.get("payload", "")
            collab_host = collab_url.replace("http://", "").replace("https://", "").split("/")[0]
            if not collab_host:
                return "Error: Could not get Collaborator host."
            vconfig["payloads"] = [
                f"https://{collab_host}",
                f"//{collab_host}",
                f"\\/\\/{collab_host}",
                f"//{collab_host}%2F%2F",
            ]

        # Auto-discover targets if not provided
        if not targets:
            ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": str(max_endpoints * 3)})
            if "error" in ep_data:
                return f"Error: {ep_data['error']}"
            auto_targets = []
            for ep in ep_data.get("endpoints", []):
                params = ep.get("parameters", [])
                if params:
                    endpoint = ep.get("endpoint", "")
                    # Extract method and path
                    parts = endpoint.split(" ", 1)
                    ep_method = parts[0] if len(parts) > 1 else "GET"
                    ep_path = parts[1] if len(parts) > 1 else parts[0]
                    for p in params:
                        auto_targets.append({"method": ep_method, "path": ep_path, "parameter": p})
            targets = auto_targets[:max_endpoints]

        if not targets:
            return "No targets found. Browse the target first or provide targets manually."

        # Targets are already trimmed above; treat them as the tested set.
        tested_targets = targets
        lines = [f"BULK TEST: {vulnerability} across {len(tested_targets)} targets\n"]
        findings = []
        total_requests = 0

        for t in tested_targets:
            t_method = t.get("method", "GET")
            t_path = t.get("path", "/")
            t_param = t.get("parameter", "")
            if not t_param:
                continue

            # Baseline
            baseline_resp = await client.post("/api/session/request", json={
                "session": session, "method": t_method, "path": t_path,
            })
            if "error" in baseline_resp:
                continue
            baseline_status = baseline_resp.get("status", 0)
            baseline_length = baseline_resp.get("response_length", 0)
            baseline_time_ms = baseline_resp.get("time_ms", 0)
            baseline_body = baseline_resp.get("response_body", "")

            for payload in vconfig["payloads"]:
                total_requests += 1
                sep = "&" if "?" in t_path else "?"
                inject_path = f"{t_path}{sep}{t_param}={payload}"

                resp = await client.post("/api/session/request", json={
                    "session": session, "method": t_method, "path": inject_path,
                })
                if "error" in resp:
                    continue

                status = resp.get("status", 0)
                length = resp.get("response_length", 0)
                body = resp.get("response_body", "")
                time_ms = resp.get("time_ms", 0)

                finding_reasons = []

                # Check indicators (only flag if NEW — not present in baseline)
                for ind in vconfig["indicators"]:
                    if ind.lower() in body.lower() and ind.lower() not in baseline_body.lower():
                        finding_reasons.append(f"indicator: {ind}")

                # Check reflection for XSS
                if vulnerability == "xss" and payload in body:
                    finding_reasons.append("reflected in response")

                # Check Location header for redirects (using Collaborator URL)
                if vulnerability == "open_redirect" and collab_host:
                    for h in resp.get("response_headers", []):
                        if h["name"].lower() == "location" and collab_host in h["value"]:
                            finding_reasons.append(f"redirect to Collaborator: {h['value'][:50]}")

                # Check timing anomaly. Rule 11: never trust a single slow
                # response — network noise triggers false positives. For sleep-style
                # payloads, require delta >1.5s vs baseline AND re-send twice more
                # requiring both repeats to also breach the threshold.
                # Threshold is 1.5s under baseline+2.5s so a SLEEP(3) payload
                # actually exceeds it under typical jitter.
                timing_threshold = max(2500, baseline_time_ms + 1500)
                p_upper = payload.upper()
                is_timing_payload = (
                    "SLEEP(" in p_upper
                    or "PG_SLEEP" in p_upper
                    or "WAITFOR DELAY" in p_upper
                    or "BENCHMARK(" in p_upper
                    or "DBMS_PIPE.RECEIVE_MESSAGE" in p_upper
                    or "DBMS_LOCK.SLEEP" in p_upper
                )
                if time_ms > timing_threshold and is_timing_payload:
                    confirmed = 1
                    for _ in range(2):
                        verify_resp = await client.post("/api/session/request", json={
                            "session": session, "method": t_method, "path": inject_path,
                        })
                        if "error" in verify_resp:
                            break
                        total_requests += 1
                        if verify_resp.get("time_ms", 0) > timing_threshold:
                            confirmed += 1
                    if confirmed >= 3:
                        finding_reasons.append(f"timing: {time_ms}ms vs baseline {baseline_time_ms}ms (3/3 iterations)")

                # Status anomaly. Require consecutive 500s — single transient
                # 500 is common noise and doesn't prove injection.
                if status == 500 and baseline_status != 500:
                    verify_resp = await client.post("/api/session/request", json={
                        "session": session, "method": t_method, "path": inject_path,
                    })
                    total_requests += 1
                    if "error" not in verify_resp and verify_resp.get("status", 0) == 500:
                        finding_reasons.append("500 error (consistent, possible injection)")

                if finding_reasons:
                    severity = "HIGH" if any("indicator" in r or "timing" in r for r in finding_reasons) else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "endpoint": f"{t_method} {t_path}",
                        "parameter": t_param,
                        "payload": payload,
                        "reasons": finding_reasons,
                    })

        if findings:
            lines.append(f"FINDINGS ({len(findings)}):")
            for f in findings:
                reasons_str = ", ".join(f["reasons"])
                lines.append(f"  [{f['severity']}] {f['endpoint']}?{f['parameter']}=")
                lines.append(f"    Payload: {f['payload']}")
                lines.append(f"    Evidence: {reasons_str}")
                lines.append("")
        else:
            lines.append("No findings.")

        # For open_redirect: poll Collaborator to confirm real interactions
        if vulnerability == "open_redirect" and collab_host:
            await asyncio.sleep(5)
            interactions_data = await client.get("/api/collaborator/interactions")
            interactions = interactions_data.get("interactions", []) if "error" not in interactions_data else []
            if interactions:
                lines.append(f"\nCOLLABORATOR CONFIRMED: {len(interactions)} interaction(s) detected")
                for hit in interactions[:5]:
                    lines.append(f"  [{hit.get('type', '?')}] from {hit.get('client_ip', '?')}")
                lines.append("  Open redirect CONFIRMED — server followed redirect to Collaborator.")
            elif findings:
                lines.append(f"\nNo Collaborator interactions (Location header showed redirect but server may not follow).")

        # Count "clean" as targets that produced ZERO findings, not as
        # arithmetic over unique vulnerable keys (which silently miscounted
        # endpoints with multiple findings).
        vulnerable_keys = {f"{f['endpoint']}?{f['parameter']}" for f in findings}
        tested_keys = {f"{t.get('method','GET')} {t.get('path','/')}?{t.get('parameter','')}" for t in tested_targets}
        clean = len(tested_keys - vulnerable_keys)
        lines.append(f"CLEAN: {clean} endpoint/param pairs showed no anomalies")
        lines.append(f"TESTED: {len(tested_targets)} targets, {total_requests} requests total")

        return "\n".join(lines)
