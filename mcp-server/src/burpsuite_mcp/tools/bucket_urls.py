"""bucket_urls_by_vuln_class — gf-pattern style URL classifier.

reconftw and gf use regex patterns to bucket a URL list into vuln-class
candidates BEFORE fuzzing. This lets auto_probe focus its budget on the
URLs most likely to hit each class, instead of trying every payload
against every URL.

Pattern signal sources:
  - param NAME           e.g. ?redirect=...   -> open_redirect
  - param VALUE shape    e.g. ?file=/etc/passwd -> lfi
  - PATH keyword         e.g. /admin/         -> admin_surface
  - REQUEST METHOD hint  e.g. POST /api/login -> auth

Output: dict[vuln_class -> list[url]] suitable for piping into
auto_probe(urls=urls, categories=[class]).
"""

import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qsl

from mcp.server.fastmcp import FastMCP


# Each class maps to (param-name regex, value-shape regex, path-keyword regex).
# A URL matches the class if ANY of the three matches.
_PATTERNS: dict[str, dict[str, str]] = {
    "xss": {
        "params": r"^(q|search|s|query|name|comment|message|content|text|body|description|title|input|keyword|term|return|callback|jsonp|tag|topic|subject)$",
        "values": r"<|>|script|onerror|onload|alert\(",
        "paths": r"/search|/comment|/post|/feedback|/contact|/forum|/blog",
    },
    "sqli": {
        "params": r"^(id|user_id|order_id|product_id|cat|category|item|pid|cid|uid|sid|gid|aid|fid|rid|page|sort|filter|orderby|order|select|column|where|table|view|book_id|article_id|news_id|story_id|topic_id)$",
        "values": r"^\d+$|^'|^\"|--|/\*",
        "paths": r"/article|/news|/product|/order|/invoice|/customer|/account|/category|/forum/topic",
    },
    "ssrf": {
        "params": r"^(url|uri|href|callback|webhook|target|destination|fetch|proxy|host|domain|server|site|address|endpoint|location|return_url|return_uri|next|redirect_url|continue|image|img|file_url|avatar_url|profile_url|src|hostname|api_url|server_url|service_url|preview|render|capture|export|import)$",
        "values": r"https?://|file://|gopher://|ftp://|dict://|sftp://|ldap://|jar://|netdoc://",
        "paths": r"/proxy|/fetch|/import|/export|/render|/preview|/capture|/avatar|/screenshot|/api/v\d/fetch",
    },
    "open_redirect": {
        "params": r"^(return|return_url|return_to|returnto|return_uri|next|continue|redirect|redirect_url|redirect_uri|redirect_to|target|destination|forward|forward_url|callback|callback_url|success_url|cancel_url|origin|referer|referrer|goto|go|out|away|landing|land|exit|jump|jumpto|location|navigate|nav|url|uri|dest|to|r|u)$",
        "values": r"^https?://|^//|^/[a-z]+",
        "paths": r"/redirect|/return|/oauth|/sso|/saml|/login|/logout|/auth/callback|/social/callback",
    },
    "lfi": {
        "params": r"^(file|filename|filepath|path|include|require|template|view|page|layout|partial|fragment|theme|skin|module|load|content|src|name|category|cat|class|locale|lang|language|country|doc|document|resource|attachment|download|export|asset|css|js)$",
        "values": r"\.\./|%2e%2e|\.\\\\|/etc/|c:\\\\|/proc/|file://",
        "paths": r"/download|/file|/attachment|/export|/import|/render|/include|/load|/asset|/static|/view|/show|/preview",
    },
    "ssti": {
        "params": r"^(template|template_name|view|name|theme|skin|format|render|content|body|message|preview|subject|email_template|notification_template|invoice_template|page_template|layout|partial|fragment|wrapper)$",
        "values": r"\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\}|@\{.*\}",
        "paths": r"/template|/render|/email|/notification|/preview|/page|/invoice",
    },
    "cmd_injection": {
        "params": r"^(cmd|command|exec|execute|run|shell|system|action|do|op|operation|process|task|job|script|module|input|args|arguments|params|payload|name|hostname|domain|target|ip|host|ping|traceroute|dns|nslookup|whois|dig|filename|file_name|filter|sort)$",
        "values": r"\$\(|`|\|\||&&|;[a-z]|\$\{IFS\}",
        "paths": r"/ping|/traceroute|/dns|/nslookup|/whois|/dig|/admin/system|/diagnostic|/healthcheck/cmd",
    },
    "xxe": {
        "params": r"^(xml|data|payload|content|body|input|file|document|doc|template|schema|wsdl|soap|svg|rss|feed|sitemap|opml|atom)$",
        "values": r"<\?xml|<!DOCTYPE|<!ENTITY",
        "paths": r"/upload|/import|/parse|/process|/api/xml|/api/soap|/wsdl|/saml|/sso/saml",
    },
    "idor": {
        "params": r"^(id|user_id|account_id|order_id|invoice_id|customer_id|patient_id|client_id|profile_id|tenant_id|org_id|workspace_id|team_id|project_id|document_id|file_id|item_id|product_id|booking_id|reservation_id|ticket_id|message_id|conversation_id|thread_id|comment_id|post_id|article_id|video_id|asset_id|uid|aid|cid|pid|oid|gid|sid|fid|rid|tid|mid|nid|hid|key|token|ref|reference)$",
        "values": r"^\d+$|^[0-9a-f]{8}-[0-9a-f]{4}|^[0-9A-HJKMNP-Z]{26}$|^\d{15,}$",
        "paths": r"/api/v\d/(users?|accounts?|orders?|invoices?|customers?|profiles?|workspaces?|teams?|projects?|documents?|files?|items?|products?|bookings?|tickets?|messages?|threads?|posts?|articles?)/",
    },
    "auth": {
        "params": r"^(login|signin|signup|password|pass|pwd|email|username|user|token|api_key|apikey|access_token|refresh_token|session|sid|sessionid|csrf|csrftoken|mfa|otp|2fa|code|verify|verification|forgot|reset|recover|magic_link)$",
        "values": r"",
        "paths": r"/login|/signin|/signup|/register|/forgot|/reset|/recover|/auth|/oauth|/sso|/saml|/2fa|/mfa|/otp|/verify",
    },
    "graphql": {
        "params": r"^(query|operationName|variables|extensions)$",
        "values": r"",
        "paths": r"/graphql|/api/graphql|/v\d/graphql|/_graphql",
    },
    "websocket": {
        "params": r"",
        "values": r"",
        "paths": r"/ws|/wss|/websocket|/socket\.io|/sockjs|/cable|/echo",
    },
    "admin_surface": {
        "params": r"",
        "values": r"",
        "paths": r"/admin|/internal|/manage|/dashboard|/console|/panel|/cms|/ops|/backoffice|/staff|/operator|/superuser|/root|/sudo",
    },
    "csrf": {
        "params": r"^(csrf_token|csrf|xsrf|_token|token|authenticity_token|__RequestVerificationToken)$",
        "values": r"",
        "paths": r"",
    },
    "file_upload": {
        "params": r"^(file|upload|attachment|image|img|photo|avatar|document|doc|media|asset|content)$",
        "values": r"",
        "paths": r"/upload|/attach|/import|/media|/avatar|/file",
    },
    "deserialization": {
        "params": r"^(data|payload|state|cookie|viewstate|__VIEWSTATE|j_id|serialized|bin|cache)$",
        "values": r"^rO0|^aced|^O:|^a:\d+:|^N\.|^\xef\xbf\xbd",
        "paths": r"",
    },
}


def _compile_patterns() -> dict[str, dict[str, re.Pattern]]:
    out = {}
    for cls, fields in _PATTERNS.items():
        out[cls] = {
            k: re.compile(v, re.I) for k, v in fields.items() if v
        }
    return out


_COMPILED = _compile_patterns()


def _classify_url(url: str) -> set[str]:
    """Return the set of vuln-class buckets this URL matches."""
    try:
        parsed = urlparse(url)
    except Exception:
        return set()
    path = parsed.path or "/"
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    hits: set[str] = set()
    for cls, patterns in _COMPILED.items():
        path_p = patterns.get("paths")
        if path_p and path_p.search(path):
            hits.add(cls)
            continue
        # Param-name match
        name_p = patterns.get("params")
        if name_p:
            for pname in params.keys():
                if name_p.search(pname):
                    hits.add(cls)
                    break
            if cls in hits:
                continue
        # Value-shape match
        val_p = patterns.get("values")
        if val_p:
            for v in params.values():
                if val_p.search(str(v)):
                    hits.add(cls)
                    break
    return hits


def register(mcp: FastMCP):

    @mcp.tool()
    async def bucket_urls_by_vuln_class(
        urls: list[str],
        include_unmatched: bool = False,
    ) -> str:
        """Classify URLs into vuln-class candidate buckets via gf-pattern style regex.

        Feed the output into auto_probe / fuzz_parameter — testing only URLs that
        match a class is 5-10x more token-efficient than spraying every payload at
        every URL.

        Args:
            urls: List of URLs to classify.
            include_unmatched: If True, also list URLs that matched no class.
        """
        if not urls:
            return "Error: empty urls list"

        buckets: dict[str, list[str]] = defaultdict(list)
        unmatched: list[str] = []
        for u in urls:
            classes = _classify_url(u)
            if not classes:
                unmatched.append(u)
                continue
            for c in classes:
                buckets[c].append(u)

        # Sort buckets by name for stable output; URLs within each bucket dedup + sort
        lines = [f"bucket_urls_by_vuln_class — {len(urls)} URLs classified", ""]
        if not buckets:
            lines.append("No URLs matched any pattern.")
            if include_unmatched:
                lines.append("\n--- Unmatched ---")
                for u in unmatched[:50]:
                    lines.append(f"  {u}")
            return "\n".join(lines)

        priority = [
            "sqli", "ssrf", "ssti", "cmd_injection", "xxe", "deserialization",
            "lfi", "xss", "open_redirect", "idor",
            "auth", "csrf", "file_upload",
            "graphql", "websocket", "admin_surface",
        ]
        ordered = [c for c in priority if c in buckets] + [c for c in buckets if c not in priority]

        total_with_class = 0
        for cls in ordered:
            urls_in_class = sorted(set(buckets[cls]))
            lines.append(f"--- {cls} ({len(urls_in_class)}) ---")
            for u in urls_in_class[:30]:
                lines.append(f"  {u}")
            if len(urls_in_class) > 30:
                lines.append(f"  ... +{len(urls_in_class)-30} more ...")
            lines.append("")
            total_with_class += len(urls_in_class)

        lines.append(f"--- Summary ---")
        lines.append(f"URLs in ≥1 bucket: {len(urls) - len(unmatched)} / {len(urls)}")
        lines.append(f"Total (URL,class) pairs: {total_with_class}")
        if include_unmatched and unmatched:
            lines.append(f"\n--- Unmatched ({len(unmatched)}) ---")
            for u in unmatched[:50]:
                lines.append(f"  {u}")
            if len(unmatched) > 50:
                lines.append(f"  ... +{len(unmatched)-50} more ...")
        lines.append("\nNext: feed each bucket into auto_probe(categories=['<class>'], urls=<list>) for targeted probing.")
        return "\n".join(lines)
