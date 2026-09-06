"""Files/deserialization/API/info-exposure/logic/crypto/AI classes for FRAMEWORK_MAP.

Data slice re-assembled by _data.py — do not import directly.
"""

from __future__ import annotations

from typing import Any

from ._row_builder import _row


_MISC: dict[str, dict[str, Any]] = {
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
