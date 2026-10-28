"""Passive proxy-history analysis — scan captured traffic for info leaks.

ZAP-style passive scan rules applied to Burp proxy history. Sends ZERO
requests — only reads what is already captured. Reports leads grouped by
issue type with proxy_history_index references.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._errors import err

_SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "XFO",
    "X-Content-Type-Options": "XCTO",
    "Referrer-Policy": "Referrer-Policy",
}

_DISCLOSURE_HEADERS = {
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "X-Backend-Server",
    "X-Debug", "X-Debug-Token", "Via",
}

_SENSITIVE_PATTERNS = [
    ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("internal_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
]

_ERROR_PATTERNS = [
    ("stack_trace", re.compile(r"(?:Traceback \(most recent|at [\w.]+\([\w.]+:\d+\)|Exception in thread|java\.lang\.\w+Exception|System\.Web\.HttpUnhandledException)", re.I)),
    ("sql_error", re.compile(r"(?:SQL syntax|mysql_fetch|pg_query|ORA-\d{5}|SQLSTATE\[|Microsoft OLE DB|Unclosed quotation mark)", re.I)),
    ("debug_info", re.compile(r"(?:DEBUG|XDEBUG|phpinfo\(\)|var_dump\(|console\.log|stack_trace)", re.I)),
    ("path_disclosure", re.compile(r"(?:/var/www/|/home/\w+/|C:\\inetpub\\|/usr/share/|/opt/\w+/)", re.I)),
]


def _check_cookies(headers: list[dict]) -> list[str]:
    """Check Set-Cookie headers for missing flags."""
    issues = []
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        if name.lower() != "set-cookie":
            continue
        cookie_lower = value.lower()
        cookie_name = value.split("=", 1)[0].strip()
        if "secure" not in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' missing Secure flag")
        if "httponly" not in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag")
        if "samesite=none" in cookie_lower:
            issues.append(f"Cookie '{cookie_name}' has SameSite=None")
    return issues


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def analyze_proxy_passive(
        domain: str = "",
        limit: int = 100,
        min_status: int = 200,
    ) -> str:
        """Passive scan of captured proxy traffic — zero requests sent.

        Reads proxy history and checks every response for info leaks,
        missing security headers, cookie issues, sensitive data patterns,
        and error signatures. Returns leads grouped by type.

        Args:
            domain: Filter to this domain (empty = all captured traffic).
            limit: Max proxy entries to analyze (default 100).
            min_status: Skip responses below this status (default 200).
        """
        params: dict = {"limit": limit}
        if domain:
            params["host"] = domain
        data = await client.get("/api/proxy/history", params=params)
        if "error" in data:
            return err(data['error'])

        entries = data.get("entries", data.get("history", []))
        if not entries:
            return "No proxy history entries to analyze."

        findings: dict[str, list[str]] = {
            "missing_headers": [],
            "server_disclosure": [],
            "cookie_issues": [],
            "sensitive_data": [],
            "error_leak": [],
            "interesting_headers": [],
        }
        analyzed = 0

        for entry in entries:
            idx = entry.get("index", entry.get("id", "?"))
            status = entry.get("status", entry.get("status_code", 0))
            if status < min_status:
                continue
            analyzed += 1

            url = entry.get("url", entry.get("path", ""))
            headers = entry.get("response_headers", [])
            if isinstance(headers, dict):
                headers = [{"name": k, "value": v} for k, v in headers.items()]

            header_names = {
                h.get("name", "").lower(): h.get("value", "")
                for h in headers if isinstance(h, dict)
            }

            # Missing security headers (only on HTML responses)
            ctype = header_names.get("content-type", "")
            if "html" in ctype or not ctype:
                for hdr, label in _SECURITY_HEADERS.items():
                    if hdr.lower() not in header_names:
                        findings["missing_headers"].append(f"#{idx} {url}: missing {label}")

            # Server/version disclosure
            for hdr in _DISCLOSURE_HEADERS:
                val = header_names.get(hdr.lower(), "")
                if val:
                    findings["server_disclosure"].append(f"#{idx} {hdr}: {val}")

            # Cookie issues
            cookie_issues = _check_cookies(headers)
            for ci in cookie_issues:
                findings["cookie_issues"].append(f"#{idx} {url}: {ci}")

            # Body checks (if available)
            body = entry.get("response_body", entry.get("body", ""))
            if body:
                body_sample = body[:10000]
                for pattern_name, regex in _SENSITIVE_PATTERNS:
                    matches = regex.findall(body_sample)
                    if matches:
                        findings["sensitive_data"].append(
                            f"#{idx} {url}: {pattern_name} ({len(matches)} match{'es' if len(matches) > 1 else ''})"
                        )
                for pattern_name, regex in _ERROR_PATTERNS:
                    if regex.search(body_sample):
                        findings["error_leak"].append(f"#{idx} {url}: {pattern_name}")

        lines = [f"Passive Analysis: {analyzed} responses scanned (zero requests sent)\n"]
        total_leads = 0
        for category, items in findings.items():
            if not items:
                continue
            unique = list(dict.fromkeys(items))[:15]
            total_leads += len(unique)
            label = category.replace("_", " ").title()
            lines.append(f"[{label}] ({len(unique)} lead{'s' if len(unique) != 1 else ''}):")
            for item in unique:
                lines.append(f"  {item}")
            lines.append("")

        if total_leads == 0:
            lines.append("No passive findings. Captured traffic looks clean.")
        else:
            lines.append(
                f"Total: {total_leads} leads. These are LEADS, not confirmed findings — "
                f"investigate each before reporting."
            )

        return "\n".join(lines)
