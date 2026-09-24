"""Pick the single most interesting keyword to search a request/response for,
for the auto-scroll+highlight screenshot (message-screenshot / screenshot_message).

Burp's editor `setSearchExpression` takes ONE expression, highlights every
occurrence and scrolls the first into view. So the job is: given the message
text (and optionally the finding's own payload), return the VERBATIM substring
present in the text that a triager most wants to see — the payload landing, an
exposed secret, an exposed path, an error, etc. Returns "" when nothing stands
out (the shot is then taken from the top of the message, still useful).

Pure and unit-tested; no I/O.
"""

from __future__ import annotations

import re

# Ranked high→low. Each returns its matched substring (what's actually in the
# text, so the editor search will find it). Highest-value evidence first: a
# proven exploit/secret beats an interesting path beats a bare long token.
_RANKED: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("passwd_file", re.compile(r"root:[^:\n]*:0:0:")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    # key = secret assignment (json / form / header): return the whole pair
    ("secret_kv", re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret|password|passwd|authorization)"
        r"[\"']?\s*[:=]\s*[\"']?[^\s\"'&,}]{6,}")),
    ("sqli_error", re.compile(
        r"(?i)you have an error in your SQL syntax|ORA-\d{5}|SQLSTATE\[|"
        r"psql:|mysql_fetch|SQLite3::|Unclosed quotation mark")),
    ("stack_trace", re.compile(
        r"(?i)Traceback \(most recent call last\)|Exception in thread|"
        r"at [\w.$]+\([A-Za-z0-9_]+\.java:\d+\)|\.php on line \d+")),
    ("interesting_path", re.compile(
        r"/(?:admin|\.git|\.env|actuator|internal|debug|api/internal|"
        r"phpinfo|server-status|wp-admin|swagger)[\w./-]*")),
    ("long_hex", re.compile(r"\b[0-9a-f]{32,}\b")),
]

_MAX = 90   # keep the search expression short enough to be a stable needle


def _clip(s: str) -> str:
    return s[:_MAX].strip()


def pick_search_term(text: str, payload: str = "",
                     extra_keywords: tuple[str, ...] = ()) -> tuple[str, str]:
    """Return (search_term, reason) — the verbatim substring to search for.

    Priority: the finding's own `payload` (proof the payload landed) → any caller
    `extra_keywords` present in the text → the ranked evidence patterns. Only ever
    returns text that is actually PRESENT (so the editor search matches). ("", "")
    when nothing stands out.
    """
    if not text:
        return "", ""
    # 1) The finding's payload reflected in the message is the strongest evidence.
    p = (payload or "").strip()
    if p and p in text:
        return _clip(p), "payload_reflected"
    # 2) Operator-named keywords, in order, if literally present.
    for kw in extra_keywords:
        k = (kw or "").strip()
        if k and k in text:
            return _clip(k), "keyword"
    # 3) Ranked evidence shapes.
    for name, pat in _RANKED:
        m = pat.search(text)
        if m:
            return _clip(m.group(0)), name
    return "", ""
