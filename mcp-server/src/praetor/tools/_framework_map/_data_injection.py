"""Injection + server-side-reach classes for FRAMEWORK_MAP.

Data slice re-assembled by _data.py — do not import directly.
"""

from __future__ import annotations

from typing import Any

from ._row_builder import _row


_INJECTION: dict[str, dict[str, Any]] = {
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
}
