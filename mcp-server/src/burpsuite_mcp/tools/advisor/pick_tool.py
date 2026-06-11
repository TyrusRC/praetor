"""pick_tool: keyword -> MCP tool resolver."""


# Map tasks to tools. Entries are checked in order, first match wins -- so
# more specific keywords (e.g. "jwt") must come BEFORE more generic ones
# (e.g. "token" which could match CSRF tokens). When ambiguous words
# appear, use multi-word anchors like "csrf token" rather than bare "token".
_MAPPINGS = [
    # ----- W30-a: CVE-aware variant sweep — wins on CVE-id keywords -----
    # Operator gap (2026-06-11): known CVE on target, public PoC needs payload
    # tweak. probe_cve_with_variants ships a bounded curated variant pack +
    # canary-echo scoring + first-CONFIRMED short-circuit.
    (["cve variant", "cve variants", "cve poc variants", "try cve poc",
      "known cve poc", "known cve payload", "poc variations",
      "poc didn't work", "poc not working", "cve poc tweak",
      "react2shell", "react 2 shell", "next-action header poc",
      "cve-2025-55182", "cve-2025-66478", "cve-2025-68130",
      "cve-2026-40175", "cve-2026-44789", "cve-2026-44790", "cve-2026-44791",
      "bounded cve sweep", "rsc poc variants", "trpc sspp poc"],
     "probe_cve_with_variants",
     "probe_cve_with_variants(cve_id='CVE-2025-55182', "
     "target_url='https://app/api/action', baseline_payload='<public PoC>', "
     "action_id='<bundle-harvested-id>', max_variants=12)"),
    # ----- W29: commercial-tool gap closures — verb-led routing FIRST -----
    # W29-a: LLM endpoint discovery + OWASP LLM Top-10 (Invicti BLOCKER closure)
    (["discover llm endpoint", "find llm endpoint", "find chat api",
      "llm api discovery", "find chat completion endpoint"],
     "discover_llm_endpoint",
     "discover_llm_endpoint(base_url='https://app.example.com/')"),
    (["owasp llm top 10", "owasp llm top-10", "llm top 10 sweep",
      "prompt injection sweep", "llm web sweep", "llm01 llm02 llm04 llm06",
      "test llm web app", "scan llm endpoint"], "run_web_llm_owasp_top10",
     "run_web_llm_owasp_top10(endpoint_url='https://app/api/chat', body_shape='openai_chat')"),
    # W29-b: gRPC active probing
    (["grpc reflection", "grpc server reflection", "list grpc services",
      "enumerate grpc methods", "grpc.reflection.v1alpha"], "probe_grpc_reflection",
     "probe_grpc_reflection(base_url='https://api.example.com')"),
    (["grpc idor", "grpc bola", "grpc id enum", "mutate grpc request",
      "grpc unauthorised access"], "probe_grpc_idor",
     "probe_grpc_idor(method_url='https://api/svc/UserService/GetUser', request_body_b64='...')"),
    # W29-c: SAML XSW
    (["saml xsw", "xml signature wrapping", "saml wrap assertion",
      "saml signature exclusion", "saml comment injection",
      "saml keyinfo swap", "samlresponse xsw"], "probe_saml_xsw",
     "probe_saml_xsw(acs_url='https://sp/saml/acs', saml_response_b64='...', attacker_nameid='admin')"),
    # W29-d: DNS rebinding
    (["dns rebind", "dns rebinding", "rbndr.us", "toctou ssrf",
      "rebind ssrf", "169.254 rebind"], "probe_dns_rebind",
     "probe_dns_rebind(target_url='https://api/fetch', url_param_name='url')"),
    # W29-e: postMessage
    (["postmessage listeners", "postmessage handler enum", "postmessage origin",
      "window.addeventlistener message", "postmessage xss",
      "cross origin message handler"], "probe_postmessage_listeners",
     "probe_postmessage_listeners(target_url='https://app.example.com/')"),
    # W29-f: CSP analyzer
    (["analyze csp", "csp bypass", "csp misconfig", "csp wildcard",
      "csp unsafe-inline", "csp jsonp escape", "csp risky cdn",
      "csp evaluator", "content security policy analysis"], "analyze_csp",
     "analyze_csp(target_url='https://app.example.com')  # or header_blob='...'"),
    # W29-g: SSE injection
    (["sse injection", "server-sent events injection", "event stream injection",
      "text/event-stream injection", "newline sse"], "probe_sse_injection",
     "probe_sse_injection(target_url='https://app/api/stream', param_name='message')"),
    # W29-h: nuclei LLM infra sweep
    (["nuclei llm", "nuclei ai templates", "nuclei mcp templates",
      "scan llm infra", "llm framework sweep", "marimo flowise langflow nuclei",
      "nuclei ollama anythingllm"], "run_nuclei_llm_infra",
     "run_nuclei_llm_infra(target='https://app.example.com', severity='medium,high,critical')"),
    # W29-j: SPNEGO / Kerberos / NTLM detection
    (["kerberos auth", "spnego auth", "ntlm auth", "ntlmv2 auth",
      "negotiate www-authenticate", "enterprise auth gateway",
      "windows integrated auth"], "probe_kerberos_spnego_auth",
     "probe_kerberos_spnego_auth(target_url='https://intranet.corp.tld/')"),
    # W29-k: MCP JSON-RPC method enumeration
    (["mcp jsonrpc methods", "mcp method enum", "wallarm mcp ultimate detect",
      "tools/list mcp", "resources/list mcp", "prompts/list mcp",
      "mcp jsonrpc enumerate"], "probe_mcp_jsonrpc_methods",
     "probe_mcp_jsonrpc_methods(endpoint_url='https://mcp.example.com/mcp')"),
    # ----- W28-b: 2026 H2 mid-year CVE intake — verb-led routing -----
    # Anchored to specific keywords so they win before generic routes
    # ("sqli" → auto_probe sqli, etc).
    (["marimo", "marimo rce", "marimo terminal", "cve-2026-39987",
      "marimo notebook rce", "marimo websocket"], "auto_probe",
     "auto_probe(session='hunt', categories=['websocket'])  "
     "# marimo_websocket_terminal_rce_2026 context; then websocket_connect + "
     "websocket_send_message('id\\n') to extract uid="),
    (["magento mirasvit", "mirasvit", "cve-2026-45247", "magento rce",
      "magento deserialization", "php unserialize gadget"], "auto_probe",
     "auto_probe(session='hunt', categories=['deserialization'])  "
     "# magento_mirasvit_php_unserialize_rce_2026 (CISA KEV active)"),
    (["vite dev", "vite devserver", "cve-2026-39365", "vite path traversal",
      "node_modules/.vite", "optimized deps map"], "auto_probe",
     "auto_probe(session='hunt', categories=['source_code_exposure'])  "
     "# vite_devserver_optimized_deps_path_traversal_2026"),
    (["nextjs websocket ssrf", "next.js websocket ssrf", "cve-2026-44578",
      "next.js ws upgrade ssrf", "websocket upgrade ssrf"], "auto_probe",
     "auto_probe(session='hunt', categories=['edge_worker_ssrf'])  "
     "# nextjs_websocket_upgrade_ssrf_2026"),
    (["illegal utf8", "illegal utf-8", "overlong utf8", "surrogate jailbreak",
      "beyond normalization", "unicode bypass waf", "unicode jailbreak llm"],
     "auto_probe",
     "auto_probe(session='hunt', categories=['ai_prompt_injection'])  "
     "# idpi_illegal_utf8_normalization_2026 (Black Hat USA 2026)"),
    (["graphql mutation aliasing", "graphql aliased mutation", "graphql rate limit bypass",
      "graphql otp brute", "graphql sms bomb", "aliased mutation account recovery"],
     "auto_probe",
     "auto_probe(session='hunt', categories=['graphql'])  "
     "# graphql_mutation_aliasing_account_recovery_dos_2026"),
    # ----- W25-b/c: 2026 H2 fresh-CVE active probes -----
    # CVE-2026-32879 passkey step-up bypass — verb-led so it wins before
    # generic "passkey" / "webauthn" routes
    (["passkey stepup", "passkey step-up", "passkey step up", "stepup bypass",
      "step-up bypass", "cve-2026-32879", "secure verification bypass",
      "passkey method bypass"], "probe_passkey_stepup_bypass",
     "probe_passkey_stepup_bypass(stepup_url='https://t/api/stepup', protected_url='https://t/api/keys', bearer_token='...')"),
    # CVE-2026-27825/27826 mcp-atlassian path traversal + header SSRF
    (["mcp-atlassian", "mcp atlassian", "cve-2026-27825", "cve-2026-27826",
      "atlassian-jira-url", "atlassian-confluence-url", "mcp server cve",
      "attachment path traversal", "atlassian mcp ssrf"], "probe_mcp_server_attacks",
     "probe_mcp_server_attacks(base_url='https://mcp-target.tld/', collaborator_url='...')"),
    # ----- W24-b: confirm_* exploit-confirmation tools (VerdictResult) -----
    # Anchor to verbs "confirm" / "prove" / "verify ... exploit" so Claude
    # reaches for these AFTER a suspected finding instead of crafting fresh
    # payloads. Each returns a VerdictResult — pipe to assess_finding directly.
    (["confirm sqli", "prove sqli", "verify sqli", "confirm sql injection",
      "sqli proof", "extract version", "extract dbms"], "confirm_sqli",
     "confirm_sqli(endpoint='https://t/x?id=1', parameter='id', dbms='mysql', strategy='union')"),
    (["confirm ssti", "prove ssti", "verify ssti", "template injection proof",
      "engine math reflection", "jinja2 confirm"], "confirm_ssti",
     "confirm_ssti(endpoint='https://t/render?q=x', parameter='q')  # tries all engines"),
    (["confirm ssrf", "prove ssrf", "verify ssrf", "ssrf callback proof"],
     "confirm_ssrf",
     "confirm_ssrf(endpoint='https://t/fetch?url=x', parameter='url', poll_seconds=5)"),
    (["confirm xxe", "prove xxe", "verify xxe", "xxe file read"], "confirm_xxe",
     "confirm_xxe(endpoint='https://t/xml', mode='inband', file_path='/etc/hostname')"),
    (["confirm rce", "prove rce", "verify rce", "confirm command injection",
      "prove command injection", "marker execution proof"], "confirm_rce",
     "confirm_rce(endpoint='https://t/x?cmd=foo', parameter='cmd', command='id', os='linux')"),
    # ----- W23-b: Metasploit Framework — operator quick-win for known CVEs -----
    # Anchor to "msf" / "metasploit" / "cve exploit" so it wins before generic vuln keywords.
    (["msf", "metasploit", "msfconsole", "msfvenom"], "msf_search",
     "msf_search(query='log4shell')  # then msf_check(module, options={'RHOSTS':'...'}) "
     "then msf_exploit(module, options={...}, require_check_first=True)"),
    (["fire metasploit", "fire msf", "msf exploit", "fire exploit module",
      "run msf exploit"], "msf_exploit",
     "msf_exploit(module='exploit/multi/http/<...>', options={'RHOSTS':'10.0.0.1','LHOST':'...'}, require_check_first=True)"),
    (["msf check", "verify with msf", "msf verify", "check exploitability"], "msf_check",
     "msf_check(module='exploit/multi/http/<...>', options={'RHOSTS':'10.0.0.1'})"),
    (["msfvenom", "generate shellcode", "encode payload", "msf payload"], "msf_payload_gen",
     "msf_payload_gen(payload='linux/x64/shell_reverse_tcp', options={'LHOST':'...','LPORT':4444}, format='python')"),
    # CVE-prefixed queries — route to MSF search by default (operator quick-win)
    # When operator says "exploit CVE-2024-XXXX", check MSF first before crafting custom.
    (["cve-2", "cve 2"], "msf_search",
     "msf_search(query='CVE-2024-XXXXX')  # MSF has hundreds of CVE-tagged modules; check first before custom payload"),
    # W23-a: Python exploit-dev sandbox (when no MSF module exists)
    (["pyexploit", "py exploit", "python exploit", "custom poc",
      "strix-style", "exploit sandbox", "burp-routed python"], "run_pyexploit",
     "run_pyexploit(script='import requests\\nrequests.post(...)', timeout_s=30)"),
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
