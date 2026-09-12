"""Response-analysis helpers for oauth_flow_simulator — kept out of the main
orchestration file so _oauth_flow_impl.py stays focused on the flow sequence.
"""

from __future__ import annotations

_STATEFUL_COOKIE_HINTS = ("state", "session", "sess", "sid", "auth", "oauth", "csrf", "login")


def scan_tossable_cookies(resp: dict) -> list[str]:
    """Set-Cookie names for state/session cookies a sibling subdomain can toss.

    Signal (OAuth Cookie Tossing, PortSwigger 2025): a stateful cookie WITHOUT
    the ``__Host-`` prefix and WITH an explicit ``Domain=`` attribute is
    overwritable from any sibling subdomain — enabling login fixation / linking.
    """
    out: list[str] = []
    for h in resp.get("response_headers", []) or []:
        if not isinstance(h, dict) or h.get("name", "").lower() != "set-cookie":
            continue
        raw = h.get("value", "") or ""
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        if name.startswith("__Host-") or name.startswith("__Secure-"):
            continue
        if "domain=" not in low:
            continue
        if any(hint in name.lower() for hint in _STATEFUL_COOKIE_HINTS):
            out.append(name)
    return out
