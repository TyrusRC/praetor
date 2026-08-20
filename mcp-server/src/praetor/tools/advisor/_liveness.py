"""Reflection-liveness / sanitizer check (false-positive reduction).

The #1 reflected-injection false positive: a payload is echoed in the response
but comes back HTML/URL/JS-encoded, so it never executes — yet a naive
"is `<script` in the body?" check flags it (and every normal HTML page already
contains its own `<script>` tags). Burp models the executable context to avoid
this; Semgrep models sanitizers. Applied black-box here: only a dangerous token
that WAS in the request and returns UN-encoded counts as live.

`reflection_liveness(payload_text, response_body)` returns `(live, sanitized)`:
tokens reflected raw (executable) vs tokens reflected only in an encoded form
(neutralized). A payload with sanitized-only reflection must not reach CONFIRMED.
"""

from __future__ import annotations

import html
from urllib.parse import quote

# DECISIVE tokens: an injection only executes if a tag-former, an
# attribute/tag breakout, or a template marker survives un-encoded. A bare event
# handler (`onerror=`) echoed raw cannot execute without one of these, so those
# are deliberately excluded to avoid false LIVE classification (and thus false
# non-suppression). Kept specific so a benign parameter never carries one.
_DANGEROUS = (
    "<script", "</script", "<svg", "<img", "<iframe", "<body", "<details",
    "'>", "\">", "{{", "${", "<%",
)


def _encoded_forms(tok: str) -> list[str]:
    """Common ways a sanitizer neutralizes `tok` in a response."""
    t = tok.lower()
    forms = {
        html.escape(tok, quote=True).lower(),        # &lt;script / &gt; / &quot;
        html.escape(tok, quote=False).lower(),       # &lt;script (no quote esc)
        quote(tok, safe="").lower(),                 # %3cscript
        t.replace("<", "\\u003c").replace(">", "\\u003e")
         .replace("\"", "\\u0022").replace("'", "\\u0027"),   # JS \u escape
        t.replace("<", "\\x3c").replace(">", "\\x3e"),        # JS \x escape
        t.replace("<", "&#60;").replace(">", "&#62;"),        # numeric entity
    }
    return [f for f in forms if f and f != t]


def reflection_liveness(payload_text: str, response_body: str) -> tuple[list[str], list[str]]:
    """Classify dangerous tokens the request carried by how they reflect.

    Returns (live, sanitized): live = reflected un-encoded (executable);
    sanitized = reflected only in an encoded/neutralized form. A token absent
    from the payload, or not reflected at all, is in neither list.
    """
    p = (payload_text or "").lower()
    b = (response_body or "").lower()
    live: list[str] = []
    sanitized: list[str] = []
    for tok in _DANGEROUS:
        if tok not in p:
            continue
        if tok in b:
            live.append(tok)
        elif any(e in b for e in _encoded_forms(tok)):
            sanitized.append(tok)
    return live, sanitized
