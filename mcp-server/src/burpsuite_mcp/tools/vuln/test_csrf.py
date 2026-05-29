"""test_csrf — orchestrate the four CSRF-defense checks in one call.

For each state-changing endpoint there are four protections; each must hold:
  1. CSRF token present in the request (form/header/cookie)
  2. Token is bound to session (replay across sessions fails)
  3. Origin / Referer header is enforced
  4. SameSite cookie is set (Lax minimum; None requires Secure)

Plus the method-override sanity check (GET-based state change). Each axis
flags independently — operator can save one finding per missing defense or
chain into ATO when paired with auth weakness.

No good third-party covers this matrix programmatically — Burp Pro has it
in the GUI but no scriptable API. This tool fills the gap.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, urlencode

from mcp.server.fastmcp import FastMCP

from ._send import send_probe
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


_TOKEN_HEADER_NAMES = (
    "x-csrf-token", "x-xsrf-token", "csrf-token", "csrftoken",
    "x-csrftoken", "x-requested-with", "anti-csrf-token", "x-anti-forgery",
)


_TOKEN_BODY_PARAMS = (
    "csrf_token", "csrf", "_token", "_csrf", "authenticity_token",
    "anti_forgery_token", "xsrf_token", "csrfmiddlewaretoken",
    "__requestverificationtoken",
)


def _find_token_in_request(headers: dict[str, str], body: str) -> tuple[str, str]:
    """Return (location, value) for any CSRF-token-like field in the request.
    location is one of: header / body / cookie / none."""
    # Headers
    for h, v in (headers or {}).items():
        if h.lower() in _TOKEN_HEADER_NAMES:
            return ("header:" + h, str(v))
    # Body — search common form/json shapes.
    if body:
        for p in _TOKEN_BODY_PARAMS:
            m = re.search(rf'[\?&]{p}=([^&]+)', body, re.IGNORECASE)
            if m:
                return ("body:" + p, m.group(1))
            m2 = re.search(rf'"{p}"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
            if m2:
                return ("body:" + p, m2.group(1))
    # Cookie (double-submit pattern)
    cookie = (headers or {}).get("Cookie", "") or (headers or {}).get("cookie", "")
    for p in ("csrf_token", "xsrf-token", "csrftoken", "_csrf"):
        m = re.search(rf'(^|;\s*){p}=([^;]+)', cookie, re.IGNORECASE)
        if m:
            return ("cookie:" + p, m.group(2))
    return ("none", "")


def _samesite_status(set_cookie_lines: list[str]) -> tuple[str, str]:
    """Parse Set-Cookie for SameSite attribute on the auth/session cookie.
    Returns (verdict, detail)."""
    if not set_cookie_lines:
        return ("absent", "no Set-Cookie issued in response (test the cookie-issuing endpoint instead)")
    for line in set_cookie_lines:
        low = line.lower()
        if not any(k in low for k in ("session", "auth", "token", "sid", "jsessionid")):
            continue
        if "samesite=strict" in low:
            return ("strict", line.split(";", 1)[0])
        if "samesite=lax" in low:
            return ("lax", line.split(";", 1)[0])
        if "samesite=none" in low:
            if "secure" in low:
                return ("none-secure", line.split(";", 1)[0])
            return ("none-insecure",
                    "SameSite=None set without Secure flag — browser rejects")
        return ("missing-attribute", line.split(";", 1)[0])
    return ("no-session-cookie", "no auth/session cookie in response")


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_csrf(  # cost: low (5-6 requests)
        url: str,
        method: str = "POST",
        body: str = "",
        cookies: dict | None = None,
        bearer_token: str = "",
        original_headers: dict | None = None,
    ) -> dict:
        """Check the four CSRF defenses against a state-changing endpoint.

        Returns VerdictResult (W7 schema): {verdict, confidence, evidence_summary,
        logger_indices, vuln_type='csrf', details, human_summary}.

        Probes:
          §1 Drop CSRF token entirely (header or body field)
          §2 Replace token with attacker-controlled garbage
          §3 Strip Origin and Referer headers
          §4 Inject hostile Origin / Referer (https://evil.tld)
          §5 GET-based state change (method swap to GET)
          §6 SameSite on the cookie-issuing response (passive check)

        Each probe fires through Burp; logger_index returned per row. A
        sensitive endpoint that 200s under §1-§5 fails the CSRF gate.

        Args:
            url: State-changing endpoint (POST/PUT/PATCH/DELETE)
            method: HTTP method (default POST)
            body: Original request body (for token detection + replay)
            cookies: Session cookies (CSRF needs authenticated session)
            bearer_token: Optional bearer auth
            original_headers: Original request headers including the CSRF token
                if one is present
        """
        if method.upper() == "GET":
            return error_verdict(
                "GET is not a state-changing method — pass POST/PUT/PATCH/DELETE",
                vuln_type="csrf",
            )

        headers = original_headers or {}
        token_loc, token_val = _find_token_in_request(headers, body)

        lines = [f"test_csrf {method} {url}\n"]
        bypasses: list[str] = []

        # Baseline (must succeed with full auth + token to make the test valid)
        baseline = await send_probe(method, url, headers, body=body,
                                    cookies=cookies, bearer=bearer_token)
        if "error" in baseline:
            return error_verdict(f"baseline failed: {baseline['error']}", vuln_type="csrf")
        b_status = baseline.get("status_code", 0)
        b_idx = baseline.get("history_index", -1)
        b_len = baseline.get("response_length", 0)
        lines.append(f"  Baseline:     {b_status} ({b_len}b, #{b_idx})  token={token_loc}={token_val[:20]+'...' if token_val else '(none)'}")

        if b_status not in (200, 201, 202, 204, 302):
            lines.append("  [!] Baseline didn't succeed — supply working "
                         "cookies + token first; re-run.")
            return error_verdict(
                f"baseline status {b_status} — supply working cookies/token first",
                vuln_type="csrf",
            ) | {"human_summary": "\n".join(lines)}

        if token_loc == "none":
            lines.append("")
            lines.append("[!!] NO CSRF TOKEN DETECTED in original request.")
            lines.append("     If baseline succeeded, the endpoint accepts "
                         "state-changing actions without a token. CSRF is "
                         "trivially exploitable from a third-party origin.")
            lines.append("     vuln_type='csrf' severity='high' "
                         f"endpoint={url}")
            bypasses.append("no token required")

        # §1 Drop token
        if token_loc.startswith("header:"):
            hname = token_loc.split(":", 1)[1]
            stripped = {k: v for k, v in headers.items() if k != hname}
            r = await send_probe(method, url, stripped, body=body,
                                 cookies=cookies, bearer=bearer_token)
        elif token_loc.startswith("body:"):
            pname = token_loc.split(":", 1)[1]
            stripped_body = re.sub(rf'[\?&]{pname}=[^&]*', '', body)
            stripped_body = re.sub(rf'"{pname}"\s*:\s*"[^"]*",?\s*', '',
                                   stripped_body)
            r = await send_probe(method, url, headers, body=stripped_body,
                                 cookies=cookies, bearer=bearer_token)
        else:
            r = None

        if r is not None:
            if "error" in r:
                lines.append(f"  §1 Drop-token:   ERROR {r['error']}")
            else:
                s = r.get("status_code", 0)
                idx = r.get("history_index", -1)
                lines.append(f"  §1 Drop-token:   {s} (#{idx})")
                if s == b_status:
                    bypasses.append(f"§1 token removal accepted (#{idx})")

        # §2 Garbage token
        if token_loc != "none":
            mutated_headers = dict(headers)
            mutated_body = body
            if token_loc.startswith("header:"):
                hname = token_loc.split(":", 1)[1]
                mutated_headers[hname] = "AAAAAAAAAA"
            elif token_loc.startswith("body:"):
                pname = token_loc.split(":", 1)[1]
                mutated_body = re.sub(rf'({pname}=)[^&]+', r'\1AAAAAAAAAA',
                                      mutated_body)
                mutated_body = re.sub(rf'("{pname}"\s*:\s*)"[^"]+"',
                                      r'\1"AAAAAAAAAA"', mutated_body)
            r = await send_probe(method, url, mutated_headers,
                                 body=mutated_body, cookies=cookies,
                                 bearer=bearer_token)
            if "error" in r:
                lines.append(f"  §2 Garbage:      ERROR {r['error']}")
            else:
                s = r.get("status_code", 0)
                idx = r.get("history_index", -1)
                lines.append(f"  §2 Garbage:      {s} (#{idx})")
                if s == b_status:
                    bypasses.append(f"§2 garbage token accepted (#{idx})")

        # §3 Strip Origin and Referer
        stripped3 = {k: v for k, v in headers.items()
                     if k.lower() not in ("origin", "referer")}
        r = await send_probe(method, url, stripped3, body=body,
                             cookies=cookies, bearer=bearer_token)
        if "error" in r:
            lines.append(f"  §3 No Origin/Ref:  ERROR {r['error']}")
        else:
            s = r.get("status_code", 0)
            idx = r.get("history_index", -1)
            lines.append(f"  §3 No Origin/Ref:  {s} (#{idx})")
            if s == b_status:
                # Acceptable IF a token is present; without a token AND no
                # origin enforcement, fully CSRF-vulnerable.
                if token_loc == "none":
                    bypasses.append(f"§3 stripped Origin/Referer accepted "
                                    f"with no token (#{idx})")

        # §4 Hostile Origin / Referer
        hostile = dict(headers)
        hostile["Origin"] = "https://evil.tld"
        hostile["Referer"] = "https://evil.tld/x"
        r = await send_probe(method, url, hostile, body=body,
                             cookies=cookies, bearer=bearer_token)
        if "error" in r:
            lines.append(f"  §4 Hostile origin: ERROR {r['error']}")
        else:
            s = r.get("status_code", 0)
            idx = r.get("history_index", -1)
            lines.append(f"  §4 Hostile origin: {s} (#{idx})")
            if s == b_status and token_loc == "none":
                bypasses.append(f"§4 hostile origin + no token (#{idx})")

        # §5 Method swap (GET-based state change)
        parsed = urlparse(url)
        # Move body fields into query if possible.
        get_url = url
        if body and "=" in body and "{" not in body:
            existing_qs = parsed.query
            joined = (existing_qs + "&" + body).lstrip("&")
            get_url = urlunparse(parsed._replace(query=joined))
        get_headers = dict(headers)
        # Drop Content-Type if it was JSON-flavoured.
        get_headers.pop("Content-Type", None)
        get_headers.pop("content-type", None)
        r = await send_probe("GET", get_url, get_headers, cookies=cookies,
                             bearer=bearer_token)
        if "error" in r:
            lines.append(f"  §5 GET method:    ERROR {r['error']}")
        else:
            s = r.get("status_code", 0)
            idx = r.get("history_index", -1)
            lines.append(f"  §5 GET method:    {s} (#{idx})")
            if s in (200, 302):
                bypasses.append(f"§5 GET-based state change accepted (#{idx})")

        # §6 SameSite passive check from baseline response headers
        set_cookie_lines: list[str] = []
        for h in baseline.get("response_headers", []) or []:
            if h.get("name", "").lower() == "set-cookie":
                set_cookie_lines.append(h.get("value", ""))
        ss_verdict, ss_detail = _samesite_status(set_cookie_lines)
        lines.append(f"  §6 SameSite:      {ss_verdict} — {ss_detail}")
        if ss_verdict in ("none-insecure", "missing-attribute"):
            bypasses.append(f"§6 SameSite={ss_verdict}")

        lines.append("")
        if bypasses:
            lines.append(f"BYPASSES ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("Save guidance:")
            lines.append("  vuln_type='csrf' severity='medium' (or 'high' if "
                         "state change is sensitive: payment / email-change / "
                         "password / 2FA toggle)")
            lines.append("  chain_with the auth boundary if it lands on a "
                         "high-impact action (per Rule 17 NEVER SUBMIT list).")
        else:
            lines.append("CSRF defenses intact across token / origin / method / SameSite.")

        human = "\n".join(lines)
        # Logger indices: baseline + each probe response (kept in lines via #N
        # markers — re-extract from the bypasses list when present).
        idx_re = re.compile(r"#(-?\d+)")
        logger_indices = [int(m) for m in idx_re.findall(human)]
        logger_indices = [i for i in logger_indices if i >= 0][:10]

        if len(bypasses) >= 2:
            verdict, confidence = "CONFIRMED", 0.85
            ev = f"CSRF defenses fail across {len(bypasses)} axes: {'; '.join(bypasses[:3])}"
        elif len(bypasses) == 1:
            verdict, confidence = "SUSPECTED", 0.55
            ev = f"single CSRF defense axis broken: {bypasses[0]}"
        else:
            verdict, confidence = "FAILED", 0.10
            ev = "CSRF defenses intact across token / origin / method / SameSite"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="csrf",
            logger_indices=logger_indices,
            details={
                "url": url, "method": method,
                "token_location": token_loc,
                "bypasses": bypasses,
                "samesite_verdict": ss_verdict,
            },
            summary=human,
        )
