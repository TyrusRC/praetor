"""pick_tool: keyword -> MCP tool resolver."""


# Map tasks to tools. Entries are checked in order, first match wins -- so
# more specific keywords (e.g. "jwt") must come BEFORE more generic ones
# (e.g. "token" which could match CSRF tokens). When ambiguous words
# appear, use multi-word anchors like "csrf token" rather than bare "token".
_MAPPINGS = [
    # ----- W22 additions (placed first so specific keywords win over generic ones) -----
    # W22-b: Computer-Use Agent (CUA) injection surface
    (["cua", "computer-use", "computer use", "claude cua", "operator agent", "atlas browser",
      "browser agent injection", "accessibility tree injection",
      "aria-label inject", "screenshot ocr injection"], "probe_cua_injection_surface",
     "probe_cua_injection_surface(url='https://target/profile', mode='passive')"),
    # W22-a: LangChain LangGrinch
    (["langgrinch", "langchain-core", "lc marker", "langchain deserial",
      "prompt template ssti", "langchain"], "auto_probe",
     "auto_probe(session='hunt', categories=['ai_prompt_injection'])  # langchain_lc_marker_injection_2025 ctx"),
    # W22-a: OpenNext / Cloudflare SSRF
    (["opennext", "cdn-cgi", "cdn cgi", "cloudflare worker image",
      "edge backslash ssrf", "cdn-cgi backslash"], "auto_probe",
     "auto_probe(session='hunt', categories=['edge_worker_ssrf'])  # opennext_cloudflare_cdn_cgi_backslash_norm_2026"),
    # W22-c: XBOW benchmark — anchor to xbow / xben so "benchmark" alone doesn't hijack
    (["xbow", "xben", "xbow benchmark", "validation benchmark"], "run_xbow_bench",
     "xbow_pull_benchmarks() then run_xbow_bench(challenge_id='XBEN-001-24', target_url='http://localhost:8080')"),
    (["autopenbench", "auto-pen-bench"], "run_autopenbench",
     "run_autopenbench(challenge_id='in-vitro-rce-1')"),
    (["caibench", "cai bench", "cybench", "nyu ctf"], "run_caibench",
     "run_caibench(suite='cybench', challenge_id='<name>')"),
    (["summarize benchmarks", "benchmark summary", "score so far", "publish score"],
     "summarize_benchmarks", "summarize_benchmarks()"),
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
     "send_to_organizer(index=<N>)  # then later: get_organizer_entries() to retrieve"),
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
    (["sqli", "sql injection"], "auto_probe",
     "auto_probe(session='hunt', categories=['sqli'])"),
    (["xss", "cross-site", "reflected"], "auto_probe",
     "auto_probe(session='hunt', categories=['xss'])"),
    (["ssrf", "server-side request"], "auto_probe",
     "auto_probe(session='hunt', categories=['ssrf'])"),
    (["ssti", "template injection"], "auto_probe",
     "auto_probe(session='hunt', categories=['ssti'])"),
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


# ----------------------------------------------------------------------
# Tier-1 hunt-loop entry points — these are the tools an operator should
# reach for first on any new target. Surfaced via `list_tier1_tools` so the
# model can default to them when no specific keyword matches.
# ----------------------------------------------------------------------
TIER1_HUNT_LOOP = [
    # Recon entry
    ("check_scope", "scope validation — call once per new domain (Rule 1)"),
    ("load_target_intel", "persistent target memory — call session-start (Rule 20a)"),
    ("discover_attack_surface", "crawl + map endpoints + risk-score params"),
    ("browser_crawl", "SPA / JS-heavy site mapping"),
    ("full_recon", "deep recon: discover + tech + secrets + headers"),
    # Probing
    ("auto_probe", "KB-driven probes across vuln categories"),
    ("quick_scan", "one-shot send + auto-analyze"),
    ("smart_analyze", "auto attack-surface analysis on a captured index"),
    # HTTP send
    ("curl_request", "default fresh request — auto Chrome 131 fingerprint"),
    ("session_request", "session-aware (cookie jar, token extraction)"),
    # Captured-first retrieval (token-efficient)
    ("get_proxy_history", "browse captured traffic"),
    ("search_history", "find captured req/resp by query"),
    ("get_request_detail", "view a single captured exchange"),
    ("extract_regex", "pull data from captured response (regex)"),
    ("extract_json_path", "pull data from JSON response"),
    ("extract_headers", "pull specific headers"),
    # Evidence + reporting
    ("annotate_request", "color + comment on a captured index (Rule 18)"),
    ("send_to_organizer", "bookmark evidence for report (Rule 18)"),
    ("send_to_repeater", "iterate visibly in Burp UI"),
    ("assess_finding", "7-question validation gate (Rule 10b)"),
    ("save_finding", "persist finding (Rule 10c)"),
    ("smart_decode", "encoding detection"),
]



async def pick_tool_impl(task: str) -> str:
    task_lower = task.lower()
    for keywords, tool, example in _MAPPINGS:
        if any(kw in task_lower for kw in keywords):
            return f"Use: {tool}\nExample: {example}"

    # Tier-1 fallback — list the core hunt-loop tools so the model can pick
    # one rather than blindly searching the 300+ tool surface.
    tier1_list = "\n".join(f"  - {name}: {desc}" for name, desc in TIER1_HUNT_LOOP[:12])
    return (
        f"No direct match for '{task}'. Tier-1 hunt-loop entry points:\n"
        f"{tier1_list}\n"
        f"  ... ({len(TIER1_HUNT_LOOP)} total — see list_tier1_tools())\n\n"
        f"Default chain: load_target_intel → discover_attack_surface → auto_probe."
    )
