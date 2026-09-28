"""Confirm-before-dangerous gate for the UNRESTRICTED raw HTTP tools.

`send_raw_request` / `curl_request` are operator-owned and bypass the confirm_*
HARD block on purpose (that block only stops irreversible payloads inside the
guided tools). But a raw send can still fire a high-risk, hard-to-reverse action
against a live target — delete a user, change a password, move money, deploy —
and the operator wanted to be ASKED first, not have it fire silently.

This is a *speed bump*, not a block: a state-changing request that matches a
high-precision dangerous-action pattern is refused ONCE with a message telling
the agent to confirm with the operator (AskUserQuestion) and re-call with
`confirmed=True`. It is deliberately narrow — GET is never dangerous, and
POST/PUT/PATCH fire only on a clear destructive/credential/money/prod signal, so
ordinary pentest traffic (login, add-to-cart, injection probes) is untouched.
DELETE is confirm-worthy by semantics (Rule 8: prove IDOR with READ, not WRITE).
"""

from __future__ import annotations

import re

# (label, pattern) — high precision. Matched against "METHOD URL\nBODY".
_DANGER: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("account/user deletion", re.compile(
        r"(?i)\b(delete|remove|deactivate|disable|purge|suspend|terminate|ban)\b"
        r"[^\n]{0,40}\b(user|account|member|tenant|customer|profile|org|subscription)s?\b")),
    ("account/user deletion", re.compile(
        r"(?i)\b(user|account|member|tenant|customer|profile|org|subscription)s?\b"
        r"[^\n]{0,20}\b(delete|deactivate|disable|remove|suspend|terminate|ban|close)\b")),
    ("account/user deletion", re.compile(
        r"(?i)\bDELETE\s+\S*/(users?|accounts?|members?|tenants?|customers?|orgs?)\b")),
    ("credential change", re.compile(
        r"(?i)\b(password|passwd|pwd|credential|api[_-]?key|secret|mfa|2fa|totp)\b"
        r"[^\n]{0,30}\b(change|reset|rotate|update|set|revoke|remove|disable)\b")),
    ("credential change", re.compile(
        r"(?i)\b(change|reset|rotate|update|set)[_-]?(password|passwd|pwd|credential|secret)\b")),
    ("credential change", re.compile(
        r"(?i)/(password|passwd|credentials?|api[_-]?keys?|secrets?|mfa|2fa|totp)\b")),
    ("money movement", re.compile(
        r"(?i)\b(charge|refund|payout|transfer|withdraw|wire|deposit|chargeback|"
        r"disburse|settlement|remit)\b")),
    ("privilege change", re.compile(
        r"(?i)\b(grant|revoke|escalate|elevate|promote|assign)\b"
        r"[^\n]{0,30}\b(admin|root|owner|superuser|role|permission|privilege|acl|sudo)")),
    ("privilege change", re.compile(
        r"(?i)\b(role|permission|privilege|acl|is[_-]?admin)\b"
        r"[^\n]{0,20}\b(admin|root|owner|superuser|grant|elevated?|true)\b")),
    ("production operation", re.compile(
        r"(?i)\b(deploy|publish|release|rollback|migrate|provision|decommission|"
        r"terminate[_-]?instance)\b")),
    ("bulk destructive action", re.compile(
        r"(?i)\b(delete|remove|purge|wipe|drop|truncate|flush)\b"
        r"[^\n]{0,20}\b(all|bulk|mass|every|entire)\b")),
    ("notification blast", re.compile(
        r"(?i)\b(send|blast|broadcast|notify)\b[^\n]{0,25}\b(all|bulk|everyone|"
        r"all[_-]?users?)\b")),
)

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def dangerous_action(method: str, url: str, body: str = "") -> str:
    """Return a short label for the dangerous action a request performs, or "".

    GET/HEAD/OPTIONS are never dangerous (no state change). DELETE is always
    confirm-worthy. POST/PUT/PATCH fire only on a high-precision danger pattern.
    """
    m = (method or "").strip().upper()
    if m not in _STATE_CHANGING:
        return ""
    # One-line blob (newlines -> spaces) so a signal that spans URL -> body
    # (e.g. path '/admin/roles' + body 'grant=admin') is caught, while the
    # bounded {0,N} gaps still keep matches local. Capped so a huge body is cheap.
    blob = re.sub(r"\s+", " ", f"{m} {url} {body or ''}")[:4000]
    for label, pat in _DANGER:
        if pat.search(blob):
            return label
    if m == "DELETE":
        return "resource deletion (DELETE)"
    return ""


_REQ_LINE = re.compile(r"^\s*([A-Z]+)\s+(\S+)")


def parse_raw(raw: str) -> tuple[str, str, str]:
    """(method, path, body) from a raw HTTP request string. Best-effort."""
    if not raw:
        return "", "", ""
    first = raw.lstrip().splitlines()[0] if raw.strip() else ""
    m = _REQ_LINE.match(first)
    method, path = (m.group(1), m.group(2)) if m else ("", "")
    # Body is after the first blank line (CRLF or LF).
    body = ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            body = raw.split(sep, 1)[1]
            break
    return method, path, body


def confirmation_notice(action: str, target: str) -> str:
    """Refusal message: this is a PAUSE for operator sign-off, not a dead end."""
    return (
        f"CONFIRM REQUIRED — this request performs a {action} against {target}. "
        "It is state-changing and potentially hard to reverse or production-"
        "affecting. Per the operator's confirm-before-dangerous policy, ASK the "
        "operator to approve this exact action (AskUserQuestion) before sending; "
        "on an explicit yes, re-call with confirmed=True. If proving impact does "
        "NOT require executing it, prove it benignly instead (Rule 8: a READ / "
        "marker already shows you could do this)."
    )
