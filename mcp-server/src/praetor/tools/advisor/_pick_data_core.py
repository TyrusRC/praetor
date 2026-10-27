"""Evidence-first + generic per-class pick_tool mappings (checked last).

Data slice re-assembled by _pick_data.py — do not import directly.
Entry order is significant (first keyword match wins).
"""


_CORE = [
    # Evidence-first: SEARCH proxy history before sending new traffic (Rule 29)
    (["find evidence", "find request", "find response", "search history", "look in history",
      "captured request", "evidence for finding", "where is the request", "did we capture",
      "proxy history", "logger entry"], "search_history",
     "search_history(query='<endpoint or string>', filter_method='POST')"),
    # Modify-and-iterate on a captured request -> Repeater (Rule 30)
    (["modify request", "tweak request", "change header", "change body", "iterate request",
      "test variation", "send to repeater", "repeater"], "send_to_repeater",
     "send_to_repeater(index=<N>, tab_name='f001-sqli-login') then repeater_resend(tab_name, modifications={...})"),
    # Volume work -> Intruder (Rule 30)
    (["brute", "brute force", "tested creds", "common creds", "default creds",
      "rate limit", "rate-limit", "ratelimit", "spam", "flood", "value enumeration",
      "header injection sweep", "send to intruder", "intruder", "attack with payloads"],
     "send_to_intruder_configured",
     "send_to_intruder_configured(index=<N>, mode='auto', payload_lists=[['admin','test','guest']], attack_type='sniper', tab_name='f002-creds')"),
    # Bookmark evidence for the report (Rule 31)
    (["bookmark", "save for report", "organize evidence", "send to organizer", "organizer",
      "remember this request"], "send_to_organizer",
     "send_to_organizer(index=<N>)  # bookmark the request in Burp's Organizer (write-only)"),
    # Read existing captured req/resp without re-sending
    (["read request", "read response", "show request", "show response",
      "view captured", "request detail"], "get_request_detail",
     "get_request_detail(index=<N>)  # use extract_regex/headers/json_path for token efficiency"),
    (["crawl", "browse", "populate history", "visit pages"], "browser_crawl",
     "browser_crawl('https://target.com', max_pages=20)"),
    # JWT first -- before any generic "token" keyword -- because "jwt token" must map to test_jwt
    (["jwt", "bearer token", "access token", "id_token", "refresh_token", "algorithm none"], "test_jwt",
     "test_jwt(token='eyJ...')"),
    # CSRF-specific token extraction uses multi-word anchors so it doesn't eat generic "token" queries
    (["csrf", "csrf token", "anti-csrf", "extract from html", "hidden field"], "extract_css_selector",
     "extract_css_selector(index, 'input[name=csrf]', attribute='value')"),
    (["header", "security header", "cors header", "cookie"], "extract_headers",
     "extract_headers(index, ['Set-Cookie', 'X-Frame-Options', 'Content-Security-Policy'])"),
    (["json", "api response", "json field", "json path"], "extract_json_path",
     "extract_json_path(index, '$.data.user.role')"),
    (["regex", "regex pattern", "extract value"], "extract_regex",
     "extract_regex(index, 'pattern_here', group=1)"),
    # ── Integrated tools: recommend the right engine for the job ──
    # Broad automated scan -> vigil (web DAST) or groma (network)
    (["scan target", "full scan", "automated scan", "dast scan", "web scan",
      "scan website", "scan application", "vulnerability scan"],
     "run_vigil",
     "run_vigil(target='https://target.com', profile='thorough')  # default web DAST, run FIRST"),
    (["port scan", "network scan", "service scan", "open ports", "scan host",
      "scan ip", "scan network", "scan server", "full port"],
     "run_groma",
     "run_groma(target='10.0.0.1')  # full port range + CVE checks, run FIRST for network targets"),
    # Specific class with a lead -> the specialized tool is faster/deeper than auto_probe
    (["sqli", "sql injection", "sqlmap"], "run_sqlmap",
     "run_sqlmap(target='http://t/?id=1', tamper='space2comment,randomcase')  "
     "# deep SQLi; also: confirm_sqli(endpoint, parameter) for quick proof, "
     "auto_probe(categories=['sqli']) for KB edge cases"),
    (["xss", "cross-site", "reflected", "dalfox"], "run_dalfox",
     "run_dalfox(target='http://t/?q=test')  "
     "# deep XSS with WAF bypass; also: confirm_xss(endpoint, parameter) for proof, "
     "auto_probe(categories=['xss']) for KB edge cases"),
    (["directory", "dir brute", "dir fuzz", "hidden files", "content discovery",
      "ffuf", "wordlist"], "run_ffuf",
     "run_ffuf(url='http://t/FUZZ', wordlist='common.txt')  # directory/file discovery"),
    (["ssrf", "server-side request"], "confirm_ssrf",
     "confirm_ssrf(endpoint='http://t/fetch?url=', parameter='url')  "
     "# confirm SSRF with 6 protocol variants; also: auto_probe(categories=['ssrf'])"),
    (["ssti", "template injection"], "confirm_ssti",
     "confirm_ssti(endpoint='http://t/', parameter='name')  "
     "# confirm SSTI across 15 engines; also: auto_probe(categories=['ssti'])"),
    (["nikto", "web server scan", "server misconfig"], "run_nikto",
     "run_nikto(target='http://t/')  # web server misconfiguration scanner"),
    (["wordpress", "wpscan", "wp plugin"], "run_wpscan",
     "run_wpscan(url='http://t/')  # WordPress vuln scanner"),
    (["nuclei", "template scan", "cve scan"], "run_vigil",
     "run_vigil(target='http://t/', templates=['/path/to/templates'])  "
     "# vigil includes nuclei templates; use --templates for custom"),
    (["command injection", "cmdi", "commix", "os command"], "run_commix",
     "run_commix(target='http://t/?cmd=test')  # deep command injection"),
    (["api fuzz", "openapi fuzz", "swagger fuzz", "api schema test"], "fuzz_api_schema",
     "fuzz_api_schema(spec_url='http://t/openapi.json')  # auto-fuzz every API endpoint"),
    (["open redirect", "unvalidated redirect"], "test_open_redirect",
     "test_open_redirect(session='hunt', path='/login', parameter='next')"),
    (["idor", "access control", "authorization"], "test_auth_matrix",
     "test_auth_matrix(endpoints=['/api/users/1','/api/users/2'], auth_states={'admin':{...},'user':{...}})"),
    (["race", "concurrent", "double spend", "toctou"], "test_race_condition",
     "test_race_condition(session='hunt', request={...}, concurrent=10)"),
    (["cors", "cross-origin"], "test_cors",
     "test_cors(session='hunt', path='/api/endpoint')"),
    # fuzz anchors are multi-word so bare "test parameter X for SQLi"
    # doesn't hijack more specific routes
    (["fuzz", "smart fuzz", "fuzz param"], "fuzz_parameter",
     "fuzz_parameter(index, parameter='param_name', smart_payloads=True)"),
    (["encode", "decode", "base64", "url encode"], "transform_chain",
     "transform_chain('input', ['url_encode', 'base64_encode'])"),
    (["waf bypass", "encoding chain", "bypass filter"], "transform_chain",
     "transform_chain('<script>alert(1)</script>', ['url_encode', 'base64_encode', 'url_encode'])"),
    # "session" keyword removed -- too generic; "login flow" / "authenticate" stay
    (["login flow", "authenticate", "login macro"], "create_macro",
     "create_macro(name='login', steps=[{method:'GET',url:'/login',extract:[...]},{method:'POST',...}])"),
    (["compare", "diff", "different response"], "compare_responses",
     "compare_responses(index1, index2, mode='full')"),
    (["annotate", "mark", "flag", "highlight"], "annotate_request",
     "annotate_request(index, color='RED', comment='Possible SQLi')"),
    (["tech stack", "technology", "framework"], "detect_tech_stack",
     "detect_tech_stack(index)"),
    (["hidden param", "parameter discovery"], "discover_hidden_parameters",
     "discover_hidden_parameters(session='hunt', method='GET', path='/endpoint')"),
    (["sensitive file", ".git", ".env", "backup"], "discover_common_files",
     "discover_common_files(session='hunt')"),
    (["report", "finding", "document"], "save_finding",
     "save_finding(title='...', description='...', severity='HIGH', endpoint='...', evidence='...')"),
]
