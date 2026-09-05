"""Request-triage signal markers + regexes (data)."""

from __future__ import annotations

import re


_SQLI_MARKERS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"\bpg_query\b", re.I),
    re.compile(r"\bSQLSTATE\[", re.I),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"\bpsycopg2\b", re.I),
    re.compile(r"\bMySQLSyntaxError", re.I),
)
_SSTI_MARKERS = (
    re.compile(r"jinja2\.exceptions"),
    re.compile(r"TemplateSyntaxError"),
    re.compile(r"freemarker\.core\."),
    re.compile(r"velocity\.exception"),
    re.compile(r"twig.error"),
)
_RCE_MARKERS = (
    re.compile(r"uid=\d+\(.+?\)\s+gid=\d+"),
    re.compile(r"\b(root|nobody|www-data|apache)\b.+\b(bash|sh|nologin)\b"),
)
_STACK_MARKERS = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"\bat\s+[\w.$]+\.[\w$]+\([\w.]+\.java:\d+\)"),
    re.compile(r"\bWhitelabel Error Page\b"),
    re.compile(r"\bServletException\b"),
    re.compile(r"NoMethodError|NameError|ReferenceError"),
    re.compile(r"Error: Cannot find module"),
    re.compile(r"FATAL:.*panic"),
)
_RSC_MARKERS = (
    re.compile(r"text/x-component", re.I),
    re.compile(r"\$\d+@"),
    re.compile(r"createServerReference"),
)
_OPEN_REDIRECT_PARAMS = {
    "url", "next", "redirect", "return", "returnTo", "return_url", "target",
    "dest", "destination", "redir", "redirect_uri", "callback", "u",
    "continue", "back", "rurl", "redirect_url",
}
_SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA|AGPA)[A-Z0-9]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b")),
    ("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt_token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key_pem",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
)

_DEBUG_HEADERS = {
    "x-debug-token", "x-debug", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-runtime", "x-version", "server",
    "x-django-debug", "x-rack-cache", "x-symfony-cache",
}
_AUTH_HEADERS = {"authorization", "x-api-key", "x-auth-token",
                 "x-access-token", "cookie", "x-csrf-token", "x-xsrf-token"}
_FORM_RE = re.compile(r"<form[^>]*>", re.I)
_HTML_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\']', re.I)


# ----- Helpers --------------------------------------------------------------


__all__ = [
    "_SQLI_MARKERS", "_SSTI_MARKERS", "_RCE_MARKERS", "_STACK_MARKERS",
    "_RSC_MARKERS", "_OPEN_REDIRECT_PARAMS", "_SECRET_PATTERNS",
    "_DEBUG_HEADERS", "_AUTH_HEADERS", "_FORM_RE", "_HTML_INPUT_RE",
]
