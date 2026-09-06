"""Access-control, auth/session and client-side classes for FRAMEWORK_MAP.

Data slice re-assembled by _data.py — do not import directly.
"""

from __future__ import annotations

from typing import Any

from ._row_builder import _row


_AUTHZ: dict[str, dict[str, Any]] = {
    "idor": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-ATHZ-04", "A01:2021-Broken Access Control", "CWE-639",
        "detection: a single session/token requests many distinct sequential object ids; 200-OK responses to resource ids the account never created (enumeration signature)",
        "index=web uri_path=\"*/api/*/*\" | rex field=uri_path \"/(?<oid>\\d+)(/|$)\" | stats dc(oid) as ids by session_id | where ids > 30",
        "AppServiceHTTPLogs | extend oid=extract(@'/(\\d+)(/|$)',1,CsUriStem) | summarize ids=dcount(oid) by CIp | where ids > 30",
    ),
    "access_control": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-ATHZ-02", "A01:2021-Broken Access Control", "CWE-285",
        "detection: low-privilege session receiving 200 on admin/privileged routes ['/admin','/internal','/manage']; forced-browsing 403→200 transitions per account",
        "index=web uri_path IN (\"/admin*\",\"/internal*\",\"/manage*\") status=200 | stats count by session_id, role, uri_path",
        "AppServiceHTTPLogs | where CsUriStem has_any ('/admin','/internal','/manage') and ScStatus == 200 | summarize by CIp, CsUriStem",
    ),
    "mass_assignment": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-BUSL-01", "A04:2021-Insecure Design", "CWE-915",
        "detection: write request (POST/PUT/PATCH) body includes privileged/immutable fields not on the intended form ['role','is_admin','isAdmin','account_balance','verified','user_id']",
        "index=web method IN (\"POST\",\"PUT\",\"PATCH\") (form_data=\"*is_admin*\" OR form_data=\"*\\\"role\\\"*\" OR form_data=\"*isAdmin*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsMethod in ('POST','PUT','PATCH') and CsBody has_any ('is_admin','\"role\"','isadmin','verified') | project CIp, CsUriStem",
    ),

    # ---- Authentication / session ----------------------------------------
    "auth_bypass": _row(
        ["T1078"], "Valid Accounts",
        "WSTG-ATHN-04", "A07:2021-Identification and Authentication Failures", "CWE-287",
        "detection: authenticated response (200 + session cookie) reached without a preceding successful credential-check event; login endpoint returning success for tampered/empty creds",
        "index=web uri_path=\"/login\" status=200 NOT [search index=auth event=login_success | fields session_id] | stats count by src_ip",
        "SigninLogs | where ResultType == 0 and AuthenticationRequirement == 'singleFactorAuthentication' | join kind=leftanti (SigninLogs | where ResultType == 50126) on CorrelationId",
    ),
    "mfa_bypass": _row(
        ["T1078"], "Valid Accounts",
        "WSTG-ATHN-04", "A07:2021-Identification and Authentication Failures", "CWE-287",
        "detection: session reaches protected resource after step-1 credential success but with no corresponding MFA-challenge-passed event; direct POST to post-MFA endpoint",
        "index=auth event=login_success NOT [search index=auth event=mfa_success | fields session_id] | stats count by user, src_ip",
        "SigninLogs | where AuthenticationRequirement == 'multiFactorAuthentication' and Status.additionalDetails == 'MFA requirement satisfied by claim in the token'",
    ),
    "jwt": _row(
        ["T1550.001"], "Use Alternate Authentication Material: Application Access Token",
        "WSTG-SESS-10", "A02:2021-Cryptographic Failures", "CWE-347",
        "detection: JWT with alg=none, alg switched (RS256->HS256), unknown kid, or unchanged signature across mutated claims; token accepted despite failed sig-verify log",
        "index=web (jwt_alg=\"none\" OR jwt_alg=\"HS256\" jwt_expected_alg=\"RS256\") OR match(_raw,\"eyJ[^.]*\\.eyJ[^.]*\\.$\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsHeaders has 'authorization: bearer eyj' | extend alg=base64_decode_tostring(extract(@'bearer (ey[^.]+)',1,CsHeaders)) | where alg has '\"alg\":\"none\"' or alg has '\"alg\":\"hs256\"'",
    ),
    "oauth": _row(
        ["T1550.001", "T1528"], "Use Alternate Authentication Material / Steal Application Access Token",
        "WSTG-ATHZ-05", "A07:2021-Identification and Authentication Failures", "CWE-863",
        "detection: OAuth redirect_uri host outside the registered allow-list; authorization code / token delivered to attacker-controlled callback; missing/reused state parameter",
        "index=web uri_path=\"*/authorize*\" NOT redirect_uri IN (\"https://app.example.com/*\") | stats count by src_ip, redirect_uri",
        "AppServiceHTTPLogs | where CsUriStem has '/authorize' and CsUriQuery has 'redirect_uri=' and not(CsUriQuery has 'redirect_uri=https%3A%2F%2Fapp.example.com')",
    ),
    "saml": _row(
        ["T1550.001"], "Use Alternate Authentication Material: Application Access Token",
        "WSTG-ATHN-04", "A07:2021-Identification and Authentication Failures", "CWE-347",
        "detection: SAMLResponse with duplicated Assertion/Signature elements (XML Signature Wrapping) or assertion whose signature does not cover the used subject; IdP-issued vs consumed subject mismatch",
        "index=web uri_path=\"*/saml/*\" (form_data=\"*<ds:Signature*<ds:Signature*\" OR form_data=\"*<saml:Assertion*<saml:Assertion*\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsUriStem has '/saml' and CsBody has 'samlresponse' | where CsBody countof('<saml:assertion') > 1",
    ),
    "csrf": _row(
        ["T1204.001"], "User Execution: Malicious Link",
        "WSTG-SESS-05", "A01:2021-Broken Access Control", "CWE-352",
        "detection: state-changing POST with a cross-origin Referer/Origin header and no valid anti-CSRF token; Origin not in the site allow-list on a mutation endpoint",
        "index=web method=\"POST\" NOT (referer=\"https://app.example.com/*\") NOT csrf_token=* | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsMethod == 'POST' and CsHeaders has 'origin:' and not(CsHeaders has 'origin: https://app.example.com') | project CIp, CsUriStem",
    ),
    "session_not_invalidated": _row(
        ["T1078"], "Valid Accounts",
        "WSTG-SESS-07", "A07:2021-Identification and Authentication Failures", "CWE-613",
        "detection: same session token used successfully after a logout event or well past the configured idle/absolute timeout",
        "index=web [search index=auth event=logout | fields session_id] status=200 | stats count by session_id, src_ip",
        "AppServiceHTTPLogs | join kind=inner (AuthLogs | where Event == 'logout') on SessionId | where TimeGenerated > LogoutTime",
    ),

    # ---- Client-side ------------------------------------------------------
    "cors": _row(
        [], "",
        "WSTG-CLNT-07", "A05:2021-Security Misconfiguration", "CWE-942",
        "detection: response reflects arbitrary Origin into Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true",
        "index=web acao=* acac=\"true\" | where acao!=\"https://app.example.com\" | stats count by src_ip, origin",
        "AppServiceHTTPLogs | where ScHeaders has 'access-control-allow-credentials: true' and ScHeaders has 'access-control-allow-origin' and not(ScHeaders has 'access-control-allow-origin: https://app.example.com')",
    ),
    "open_redirect": _row(
        ["T1204.001"], "User Execution: Malicious Link",
        "WSTG-CLNT-04", "A01:2021-Broken Access Control", "CWE-601",
        "detection: redirect/return/next/url param holds an absolute off-site URL and the response is a 30x Location to that external host",
        "index=web (uri_query=\"*redirect=http*\" OR uri_query=\"*next=//*\" OR uri_query=\"*url=http*\") status=30* | stats count by src_ip, location",
        "AppServiceHTTPLogs | where ScStatus between (300 .. 399) and CsUriQuery has_any ('redirect=http','next=//','returnurl=http','url=http') | project CIp, CsUriStem, CsUriQuery",
    ),
    "websocket": _row(
        [], "",
        "WSTG-CLNT-10", "A01:2021-Broken Access Control", "CWE-1385",
        "detection: WebSocket Upgrade whose Origin header is missing or not in the allow-list (cross-site WebSocket hijacking); handshake succeeds without auth cookie/token",
        "index=web upgrade=\"websocket\" NOT (origin=\"https://app.example.com\") | stats count by src_ip, origin",
        "AppServiceHTTPLogs | where CsHeaders has 'upgrade: websocket' and not(CsHeaders has 'origin: https://app.example.com') | project CIp, CsUriStem",
    ),
    "postmessage_listener": _row(
        ["T1059.007"], "Command and Scripting Interpreter: JavaScript",
        "WSTG-CLNT-11", "A03:2021-Injection", "CWE-345",
        "detection: client-side only — window.addEventListener('message') handler with no event.origin check reaching a DOM/eval sink; audit via source review or DAST, not server logs",
        "// client-side: static-analyse JS for addEventListener('message') without event.origin allow-list check",
        "// client-side: no server log signal; use CSP violation telemetry as a weak proxy",
    ),
}
