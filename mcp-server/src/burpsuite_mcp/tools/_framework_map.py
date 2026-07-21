"""Framework tagging + blue-team detection pairing for Praetor findings (W34-b).

ONE lookup table keyed by `vuln_type`. Turns a red-team finding into a
purple-team deliverable: each class carries its MITRE ATT&CK technique,
OWASP WSTG test id, OWASP Top 10 2021 category, primary CWE, and a paired
Sigma / Splunk-SPL / Microsoft-KQL detection rule describing how a defender
spots THIS attack in web / proxy / WAF logs.

Design (lazy/surgical): the 150 KB JSON files are NOT edited. This module is
pure data + a fuzzy resolver so consumers (report builder, SARIF exporter)
call one function.

Sources:
  - MITRE ATT&CK Enterprise v15 technique IDs (real IDs only). Web LLM classes
    use MITRE ATLAS (AML.T*) which is the ATT&CK-aligned adversarial-ML matrix.
  - OWASP WSTG v4.2 test ids (WSTG-<category>-<nn>).
  - OWASP Top 10 2021.
  - CWE primary weakness.

`framework_tags(vuln_type)` resolves exact → alias → suffix-strip → prefix
fallback, and always returns a well-formed row (empty defaults if unknown).
"""

from __future__ import annotations

from typing import Any

# Canonical empty row shape. Consumers rely on these keys always existing.
_DEFAULT_ROW: dict[str, Any] = {
    "attack_ck": [],      # list[str] of MITRE ATT&CK / ATLAS technique IDs
    "attack_name": "",    # human name of the primary technique
    "wstg": "",           # OWASP WSTG test id (or "")
    "owasp": "",          # OWASP Top 10 2021 category
    "cwe": "",            # primary CWE id
    "detection": {},      # {sigma, spl, kql}
}


def _row(
    attack_ck: list[str],
    attack_name: str,
    wstg: str,
    owasp: str,
    cwe: str,
    sigma: str,
    spl: str,
    kql: str,
) -> dict[str, Any]:
    return {
        "attack_ck": attack_ck,
        "attack_name": attack_name,
        "wstg": wstg,
        "owasp": owasp,
        "cwe": cwe,
        "detection": {"sigma": sigma, "spl": spl, "kql": kql},
    }


# ---------------------------------------------------------------------------
# The lookup table. ~40 core classes.
# ---------------------------------------------------------------------------
FRAMEWORK_MAP: dict[str, dict[str, Any]] = {
    # ---- Injection --------------------------------------------------------
    "sqli": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-05", "A03:2021-Injection", "CWE-89",
        "detection: cs-uri-query contains any of ['UNION SELECT','information_schema','SLEEP(','WAITFOR DELAY',\"' OR '1'='1\",'/*!','xp_cmdshell'] OR response status 500 with DB error string",
        "index=web (uri_query=\"*UNION*SELECT*\" OR uri_query=\"*information_schema*\" OR uri_query=\"*SLEEP(*\" OR uri_query=\"*'%20OR%20'1'='1*\") | stats count values(uri_path) by src_ip",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('union select','information_schema','sleep(','waitfor delay',\"' or '1'='1\") | summarize hits=count() by CIp, CsUriStem",
    ),
    "xss": _row(
        ["T1059.007", "T1539"], "Command and Scripting Interpreter: JavaScript",
        "WSTG-INPV-01", "A03:2021-Injection", "CWE-79",
        "detection: cs-uri-query OR request body contains any of ['<script','onerror=','javascript:','onload=','<img src=x','document.cookie','<svg/onload']",
        "index=web (uri_query=\"*<script*\" OR uri_query=\"*onerror=*\" OR uri_query=\"*javascript:*\" OR form_data=\"*document.cookie*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('<script','onerror=','javascript:','onload=','document.cookie') | project TimeGenerated, CIp, CsUriStem, CsUriQuery",
    ),
    "dom_xss": _row(
        ["T1059.007"], "Command and Scripting Interpreter: JavaScript",
        "WSTG-CLNT-01", "A03:2021-Injection", "CWE-79",
        "detection: URL fragment / query reaching a DOM sink; hunt client-side via CSP report-uri violations for inline-script / eval blocked directives",
        "index=csp_reports (violated_directive=\"script-src*\" OR blocked_uri=\"*eval*\" OR blocked_uri=\"inline\") | stats count by document_uri, source_file",
        "AppServiceHTTPLogs | where CsUriStem has '#' or CsUriQuery has_any ('javascript:','data:text/html') | summarize by CIp, CsUriStem",
    ),
    "ssti": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-18", "A03:2021-Injection", "CWE-1336",
        "detection: request param contains template syntax ['{{7*7}}','${','#{','<%=','{%'] OR response reflects arithmetic product (e.g. 49) not present in request",
        "index=web (uri_query=\"*{{*}}*\" OR uri_query=\"*${*}*\" OR uri_query=\"*<%=*\" OR form_data=\"*#{*}*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('{{','${','<%=','#{','{%') | project TimeGenerated, CIp, CsUriStem",
    ),
    "xxe": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-07", "A05:2021-Security Misconfiguration", "CWE-611",
        "detection: XML request body contains '<!DOCTYPE' or '<!ENTITY' or 'SYSTEM' with file:// or http:// external reference; correlate with outbound DNS/HTTP to internal or attacker host",
        "index=web content_type=\"*xml*\" (form_data=\"*<!ENTITY*\" OR form_data=\"*SYSTEM*file://*\" OR form_data=\"*<!DOCTYPE*\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsContentType has 'xml' and CsBytes > 0 | join (DnsEvents | where Name has_any ('.internal','169.254.169.254')) on $left.CIp == $right.ClientIP",
    ),
    "rce": _row(
        ["T1190", "T1059"], "Exploit Public-Facing Application / Command and Scripting Interpreter",
        "WSTG-INPV-11", "A03:2021-Injection", "CWE-94",
        "detection: request param contains OS/lang exec tokens ['system(','exec(','eval(','`id`','$(','\\|nslookup','phpinfo(']; on host, web-server process (php/node/python/java) spawning /bin/sh|cmd.exe|nslookup|curl",
        "index=web (uri_query=\"*system(*\" OR uri_query=\"*exec(*\" OR form_data=\"*$(*\") | stats count by src_ip | join src_ip [search index=edr parent_process IN (\"php-fpm\",\"node\",\"python\",\"java\") child_process IN (\"sh\",\"bash\",\"cmd.exe\")]",
        "DeviceProcessEvents | where InitiatingProcessFileName in~ ('php-fpm.exe','node.exe','w3wp.exe','java.exe') and FileName in~ ('cmd.exe','powershell.exe','sh','bash')",
    ),
    "command_injection": _row(
        ["T1059"], "Command and Scripting Interpreter",
        "WSTG-INPV-12", "A03:2021-Injection", "CWE-78",
        "detection: request param contains shell metacharacters/commands [';id',';whoami','|nslookup','&&curl','`','$(','%0a']; correlate web-server child processes",
        "index=web (uri_query=\"*;id*\" OR uri_query=\"*|nslookup*\" OR uri_query=\"*&&*\" OR uri_query=\"*`*`*\") | stats count by src_ip, uri_path",
        "DeviceProcessEvents | where InitiatingProcessFileName in~ ('w3wp.exe','httpd','nginx','node.exe') and FileName in~ ('cmd.exe','bash','sh','nslookup','curl','wget')",
    ),
    "crlf_injection": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-15", "A03:2021-Injection", "CWE-93",
        "detection: request param contains encoded CRLF ['%0d%0a','%0a','\\r\\n'] followed by header-like text (Set-Cookie/Location); response echoes an injected header",
        "index=web (uri_query=\"*%0d%0a*\" OR uri_query=\"*%0aSet-Cookie*\" OR uri_query=\"*%0aLocation*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('%0d%0a','%0aset-cookie','%0alocation') | project TimeGenerated, CIp, CsUriStem",
    ),
    "ldap_injection": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-06", "A03:2021-Injection", "CWE-90",
        "detection: auth/search param contains LDAP filter metachars ['*)(','|(','&(', ')(uid=*','(&(objectClass=']",
        "index=web (uri_query=\"*)(uid=*\" OR uri_query=\"*)(objectClass=*\" OR form_data=\"*|(*\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsUriQuery has_any (')(uid=','(objectclass=','*)(') | summarize by CIp, CsUriStem",
    ),
    "xpath_injection": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-09", "A03:2021-Injection", "CWE-91",
        "detection: request param contains XPath metachars [\"' or '1'='1\",'or 1=1','count(','//*','string-length(']",
        "index=web (form_data=\"*' or '1'='1*\" OR uri_query=\"*count(*\" OR uri_query=\"*//*[*\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsUriQuery has_any (\"' or '1'='1\",'count(','string-length(') | project CIp, CsUriStem",
    ),
    "nosql": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-05", "A03:2021-Injection", "CWE-943",
        "detection: JSON body or param contains Mongo/NoSQL operators ['$ne','$gt','$where','$regex','[$ne]'] in a login/query field",
        "index=web (form_data=\"*$ne*\" OR form_data=\"*$where*\" OR form_data=\"*$regex*\" OR uri_query=\"*[$ne]*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('$ne','$gt','$where','$regex') | summarize by CIp, CsUriStem",
    ),
    "parameter_pollution": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-04", "A03:2021-Injection", "CWE-235",
        "detection: same query/body parameter name appears more than once in a single request",
        "index=web | eval dupes=mvcount(split(uri_query,\"&\")) | where match(uri_query,\"(^|&)(\\w+)=[^&]*&\\2=\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery matches regex @'(^|&)(\\w+)=[^&]*&\\2=' | project CIp, CsUriStem, CsUriQuery",
    ),

    # ---- SSRF / server-side reach -----------------------------------------
    "ssrf": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-19", "A10:2021-Server-Side Request Forgery", "CWE-918",
        "detection: URL-valued param points at internal/metadata targets ['169.254.169.254','metadata.google','localhost','127.0.0.1','file://','0.0.0.0','[::1]']; correlate app egress to link-local/RFC1918",
        "index=web (uri_query=\"*169.254.169.254*\" OR uri_query=\"*metadata.google*\" OR uri_query=\"*localhost*\" OR uri_query=\"*file://*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('169.254.169.254','metadata.google.internal','127.0.0.1','file://','[::1]') | project TimeGenerated, CIp, CsUriStem",
    ),
    "host_header": _row(
        ["T1557"], "Adversary-in-the-Middle",
        "WSTG-INPV-17", "A05:2021-Security Misconfiguration", "CWE-644",
        "detection: Host / X-Forwarded-Host / X-Forwarded-Server header does not match the served vhost allow-list; password-reset links built from attacker Host",
        "index=web NOT (host IN (\"app.example.com\",\"www.example.com\")) OR x_forwarded_host=* | stats count by src_ip, host, x_forwarded_host",
        "AppServiceHTTPLogs | where CsHost !in~ ('app.example.com','www.example.com') | summarize count() by CIp, CsHost",
    ),
    "request_smuggling": _row(
        ["T1190", "T1557"], "Exploit Public-Facing Application / Adversary-in-the-Middle",
        "WSTG-INPV-15", "A05:2021-Security Misconfiguration", "CWE-444",
        "detection: request carries both Content-Length and Transfer-Encoding, or duplicated/obfuscated Transfer-Encoding (TE.CL / CL.TE); front-end vs back-end request-count mismatch",
        "index=web (transfer_encoding=* content_length=*) OR match(_raw,\"Transfer-Encoding:.*\\n.*Transfer-Encoding:\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsHeaders has 'transfer-encoding' and CsHeaders has 'content-length' | project TimeGenerated, CIp, CsUriStem",
    ),

    # ---- Access control / authZ -------------------------------------------
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

    # ---- Files / traversal / upload ---------------------------------------
    "path_traversal": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-ATHZ-01", "A01:2021-Broken Access Control", "CWE-22",
        "detection: file/path param contains traversal sequences ['../','..%2f','%2e%2e/','..\\\\','/etc/passwd','C:\\\\Windows','....//']",
        "index=web (uri_query=\"*../*\" OR uri_query=\"*..%2f*\" OR uri_query=\"*/etc/passwd*\" OR uri_query=\"*%2e%2e*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('../','..%2f','%2e%2e','/etc/passwd','..\\\\') | project TimeGenerated, CIp, CsUriStem",
    ),
    "file_upload": _row(
        ["T1190", "T1505.003"], "Exploit Public-Facing Application / Web Shell",
        "WSTG-BUSL-09", "A04:2021-Insecure Design", "CWE-434",
        "detection: multipart upload with executable extension/content-type (.php,.jsp,.aspx,.svg,.phtml) or magic-byte mismatch; new file in web-root followed by a request that executes it",
        "index=web method=\"POST\" content_type=\"*multipart*\" (form_data=\"*.php*\" OR form_data=\"*.jsp*\" OR form_data=\"*.phtml*\") | stats count by src_ip, uri_path",
        "DeviceFileEvents | where FolderPath has_any ('wwwroot','htdocs','/var/www') and FileName endswith_any ('.php','.jsp','.aspx','.phtml')",
    ),

    # ---- Deserialization / pollution --------------------------------------
    "deserialization": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-11", "A08:2021-Software and Data Integrity Failures", "CWE-502",
        "detection: request body/cookie carries serialized-object markers ['rO0AB' (Java b64),'aced0005' (Java hex),'O:8:' (PHP),'__reduce__','pickle']; web process spawns unexpected children",
        "index=web (form_data=\"*rO0AB*\" OR form_data=\"*aced0005*\" OR cookie=\"*O:8:*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsBody has_any ('ro0ab','aced0005','o:8:','__reduce__') | project CIp, CsUriStem",
    ),
    "prototype_pollution": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-INPV-11", "A08:2021-Software and Data Integrity Failures", "CWE-1321",
        "detection: JSON body or query contains prototype keys ['__proto__','constructor','prototype'] as object keys or bracket/dotted param names",
        "index=web (form_data=\"*__proto__*\" OR uri_query=\"*constructor[prototype]*\" OR uri_query=\"*__proto__*\") | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where CsUriQuery has_any ('__proto__','constructor[prototype]','prototype[') or CsBody has '__proto__' | project CIp, CsUriStem",
    ),
    "cache_poisoning": _row(
        ["T1557"], "Adversary-in-the-Middle",
        "WSTG-CONF-11", "A05:2021-Security Misconfiguration", "CWE-444",
        "detection: unkeyed header (X-Forwarded-Host / X-Forwarded-Scheme / custom) reflected into a cacheable (Cache-Control: public / hit) response; poisoned entry served to other clients",
        "index=web cache_status=\"HIT\" (x_forwarded_host=* OR x_forwarded_scheme=*) | stats count by uri_path, x_forwarded_host",
        "AppServiceHTTPLogs | where ScHeaders has 'x-cache: hit' and CsHeaders has_any ('x-forwarded-host','x-forwarded-scheme') | project CsUriStem, CsHeaders",
    ),

    # ---- API / GraphQL ----------------------------------------------------
    "graphql": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-APIT-01", "A03:2021-Injection", "CWE-200",
        "detection: POST to /graphql with introspection query ('__schema','__type'), deeply nested/aliased fields (DoS), or batched operations array",
        "index=web uri_path=\"*/graphql*\" (form_data=\"*__schema*\" OR form_data=\"*__type*\" OR form_data=\"*[{*query*}*{*query*}*\") | stats count by src_ip",
        "AppServiceHTTPLogs | where CsUriStem has '/graphql' and CsBody has_any ('__schema','__type','mutation') | project CIp, CsBody",
    ),

    # ---- Info exposure / config -------------------------------------------
    "info_disclosure": _row(
        ["T1213"], "Data from Information Repositories",
        "WSTG-INFO-05", "A05:2021-Security Misconfiguration", "CWE-200",
        "detection: response body/headers leak stack traces, internal paths, framework versions, or PII fields on error/verbose responses (status 500 with exception text)",
        "index=web status>=500 (response=\"*Exception*\" OR response=\"*Traceback*\" OR response=\"*at java.*\" OR response=\"*stack trace*\") | stats count by uri_path",
        "AppServiceHTTPLogs | where ScStatus >= 500 | join (AppServiceConsoleLogs | where ResultDescription has_any ('Exception','Traceback','stack trace')) on _ResourceId",
    ),
    "source_code_exposure": _row(
        ["T1213"], "Data from Information Repositories",
        "WSTG-CONF-04", "A05:2021-Security Misconfiguration", "CWE-540",
        "detection: 200-OK requests for VCS/backup/config artifacts ['/.git/','/.env','/.svn/','.bak','.old','/config.php~','/.DS_Store']",
        "index=web uri_path IN (\"/.git/*\",\"/.env\",\"/.svn/*\",\"*.bak\",\"*~\",\"/.DS_Store\") status=200 | stats count by src_ip, uri_path",
        "AppServiceHTTPLogs | where ScStatus == 200 and CsUriStem has_any ('/.git/','/.env','/.svn/','.bak','.old','/.ds_store') | project CIp, CsUriStem",
    ),
    "subdomain_takeover": _row(
        ["T1584.001"], "Compromise Infrastructure: Domains",
        "WSTG-CONF-10", "A05:2021-Security Misconfiguration", "CWE-350",
        "detection: DNS CNAME points to a de-provisioned SaaS host serving a provider 'no such bucket/app' fingerprint (NoSuchBucket, 'There isn't a GitHub Pages site here', Heroku 'no such app')",
        "index=dns record_type=CNAME target IN (\"*.s3.amazonaws.com\",\"*.github.io\",\"*.herokuapp.com\") | join target [search index=web response=\"*NoSuchBucket*\" OR response=\"*no such app*\"]",
        "DnsEvents | where RecordType == 'CNAME' and Name has_any ('.s3.amazonaws.com','.github.io','.herokuapp.com','.azurewebsites.net')",
    ),

    # ---- Business logic / timing / rate -----------------------------------
    "race_condition": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-BUSL-04", "A04:2021-Insecure Design", "CWE-362",
        "detection: burst of near-simultaneous (<100ms apart) identical state-changing requests from one session on a limited resource (coupon, balance, vote); duplicate-effect anomaly",
        "index=web method=\"POST\" uri_path=\"*/redeem*\" | transaction session_id maxspan=200ms | where eventcount > 2 | stats count by session_id",
        "AppServiceHTTPLogs | where CsMethod == 'POST' | summarize c=count() by CIp, CsUriStem, bin(TimeGenerated, 200ms) | where c > 2",
    ),
    "business_logic": _row(
        ["T1190"], "Exploit Public-Facing Application",
        "WSTG-BUSL-01", "A04:2021-Insecure Design", "CWE-840",
        "detection: workflow-invariant break — checkout/step endpoints hit out of order or with tampered price/quantity (negative qty, altered total); server-side amount != catalog price",
        "index=web uri_path=\"*/checkout*\" (form_data=\"*quantity=-*\" OR form_data=\"*price=0*\" OR form_data=\"*amount=0.01*\") | stats count by session_id",
        "AppServiceHTTPLogs | where CsUriStem has '/checkout' and CsBody has_any ('quantity=-','price=0','amount=0') | project CIp, CsBody",
    ),
    "rate_limit": _row(
        ["T1110"], "Brute Force",
        "WSTG-BUSL-05", "A04:2021-Insecure Design", "CWE-799",
        "detection: high request volume to a sensitive endpoint (login, OTP, promo) from one src/session within a short window with no 429 responses",
        "index=web uri_path IN (\"/login\",\"/otp\",\"/verify\") | stats count by src_ip, bin(_time,1m) | where count > 60",
        "AppServiceHTTPLogs | where CsUriStem has_any ('/login','/otp','/verify') | summarize c=count() by CIp, bin(TimeGenerated,1m) | where c > 60",
    ),

    # ---- Crypto -----------------------------------------------------------
    "crypto_weakness": _row(
        [], "",
        "WSTG-CRYP-04", "A02:2021-Cryptographic Failures", "CWE-327",
        "detection: sensitive tokens/cookies with predictable structure, short entropy, or MD5/SHA1-length hashes; TLS negotiated to weak cipher (config-scan signal)",
        "index=web set_cookie=* | eval entropy=len(session_token) | where entropy < 16 | stats count by src_ip",
        "AppServiceHTTPLogs | where ScHeaders has 'set-cookie' | extend tok=extract(@'session=([^;]+)',1,ScHeaders) | where strlen(tok) < 16",
    ),

    # ---- LLM / AI (MITRE ATLAS) -------------------------------------------
    "ai_prompt_injection": _row(
        ["AML.T0051"], "LLM Prompt Injection (MITRE ATLAS)",
        "", "A03:2021-Injection", "CWE-1427",
        "detection: LLM prompt/completion logs containing injection markers ['ignore previous instructions','system prompt','you are now','disregard','override']; tool-call arguments diverging from user intent",
        "index=llm_prompts (prompt=\"*ignore previous instructions*\" OR prompt=\"*disregard*\" OR prompt=\"*system prompt*\" OR prompt=\"*you are now*\") | stats count by user, session_id",
        "// LLM gateway logs: where PromptText has_any ('ignore previous instructions','system prompt','you are now','disregard')",
    ),
}


# ---------------------------------------------------------------------------
# Aliases: variant vuln_type -> canonical key in FRAMEWORK_MAP.
# ---------------------------------------------------------------------------
_ALIASES: dict[str, str] = {
    "rce_detection": "rce",
    "command_execution": "command_injection",
    "cmdi": "command_injection",
    "os_command_injection": "command_injection",
    "insecure_deserialization": "deserialization",
    "sql_injection": "sqli",
    "blind_sqli": "sqli",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "cross_site_scripting": "xss",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "directory_traversal": "path_traversal",
    "hpp": "parameter_pollution",
    "http_parameter_pollution": "parameter_pollution",
    "http_desync": "request_smuggling",
    "smuggling": "request_smuggling",
    "cswsh": "websocket",
    "ws_no_auth": "websocket",
    "ws_token_in_url": "websocket",
    "csp_missing": "info_disclosure",
    "csp_misconfig": "cors",
    "dom_security_signals": "dom_xss",
    "authentication": "auth_bypass",
    "login_bypass": "auth_bypass",
    "saml_xsw": "saml",
    "webauthn_passkey": "auth_bypass",
    "passkey_stepup_bypass": "mfa_bypass",
    "oauth_chain_attacks": "oauth",
    "trpc_sspp": "prototype_pollution",
    "nextjs_cache_poisoning": "cache_poisoning",
    "state_machine_race": "race_condition",
    "stale_privilege": "access_control",
    "bola": "idor",
    "bopla": "idor",
    "bfla": "access_control",
    "grpc_idor": "idor",
    "cross_transport_idor": "idor",
    "nosql_injection": "nosql",
    "mongodb_injection": "nosql",
    "graphql_csrf": "csrf",
    "graphql_entities_injection": "graphql",
    "postmessage": "postmessage_listener",
    "rag_injection": "ai_prompt_injection",
    "web_llm": "ai_prompt_injection",
    "local_llm_prompt_injection": "ai_prompt_injection",
    "weak_token_generation": "crypto_weakness",
    "payment_flow": "business_logic",
    "webhook_replay": "business_logic",
    "id_enumeration": "idor",
}

# Suffixes stripped by the fuzzy resolver (order matters — longest first).
_STRIP_SUFFIXES = (
    "_detection", "_confirm", "_probe", "_blind", "_time", "_timing",
    "_v2", "_check", "_test", "_scan", "_bypass", "_injection", "_attack",
    "_attacks", "_leak", "_misconfig",
)


def framework_tags(vuln_type: str) -> dict[str, Any]:
    """Return the framework-tagging row for a Praetor ``vuln_type``.

    Resolution order:
      1. exact match in FRAMEWORK_MAP
      2. alias table
      3. suffix stripping (``sqli_blind`` -> ``sqli``), re-checking map + aliases
      4. first-token prefix (``sqli_something`` -> ``sqli``)
    Always returns a well-formed row; unknown classes get empty defaults so
    callers never KeyError. Returned dict is a shallow-independent copy.

    Args:
        vuln_type: finding vuln_type / vulnerability class (case-insensitive).
    """
    if not vuln_type or not isinstance(vuln_type, str):
        return _copy_row(_DEFAULT_ROW)

    key = vuln_type.strip().lower()

    row = _lookup(key)
    if row is not None:
        return _copy_row(row)

    # 3. progressively strip known suffixes.
    stripped = key
    changed = True
    while changed:
        changed = False
        for suf in _STRIP_SUFFIXES:
            if stripped.endswith(suf) and len(stripped) > len(suf):
                stripped = stripped[: -len(suf)]
                changed = True
                row = _lookup(stripped)
                if row is not None:
                    return _copy_row(row)

    # 4. first-token prefix fallback (e.g. "sqli_second_order" -> "sqli").
    if "_" in key:
        head = key.split("_", 1)[0]
        row = _lookup(head)
        if row is not None:
            return _copy_row(row)

    return _copy_row(_DEFAULT_ROW)


def _lookup(key: str) -> dict[str, Any] | None:
    """Exact or alias lookup. Returns the shared row (caller must copy)."""
    if key in FRAMEWORK_MAP:
        return FRAMEWORK_MAP[key]
    alias = _ALIASES.get(key)
    if alias and alias in FRAMEWORK_MAP:
        return FRAMEWORK_MAP[alias]
    return None


def _copy_row(row: dict[str, Any]) -> dict[str, Any]:
    """Independent copy so mutation by a caller never corrupts the table."""
    return {
        "attack_ck": list(row["attack_ck"]),
        "attack_name": row["attack_name"],
        "wstg": row["wstg"],
        "owasp": row["owasp"],
        "cwe": row["cwe"],
        "detection": dict(row["detection"]),
    }


def attack_tag_list(vuln_type: str) -> list[str]:
    """SARIF/tag-friendly flat tags: ``['attack:T1190','wstg:WSTG-INPV-05','cwe:CWE-89']``."""
    row = framework_tags(vuln_type)
    tags = [f"attack:{t}" for t in row["attack_ck"]]
    if row["wstg"]:
        tags.append(f"wstg:{row['wstg']}")
    if row["cwe"]:
        tags.append(f"cwe:{row['cwe']}")
    return tags
