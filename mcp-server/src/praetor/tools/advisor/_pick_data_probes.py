"""Commercial-gap active probes, CVE intake, confirm_*, Metasploit, benchmark pick_tool mappings.

Data slice re-assembled by _pick_data.py — do not import directly.
Entry order is significant (first keyword match wins).
"""


_PROBES = [
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
    # Spec F1: author + run an ad-hoc probe the hand-authored KB doesn't cover yet
    (["adhoc probe", "custom probe", "generate probe", "nl probe",
      "new technique no kb", "test fresh cve", "author matcher",
      "probe without kb"], "run_adhoc_probe",
     "run_adhoc_probe(context_name='cve_x', probes=[{'payload':'...','matchers':[{'type':'word','words':['marker']}]}], targets=[{'url':'...'}])"),
    # Spec E: one-call situational orientation for the agent (recon-intel map)
    (["orient", "situational awareness", "target brief", "context map",
      "where am i", "quick context", "understand target", "resume target",
      "pick up domain", "orientation"], "target_brief",
     "target_brief(domain='app.example.com')"),
    # D1: invisible-unicode concealment in MCP tool metadata (TAG-block / ZW / bidi)
    (["mcp invisible unicode", "tool metadata concealment", "tag block unicode",
      "hidden unicode tool description", "mcp tool poisoning unicode",
      "zero width tool name", "mcptox"], "detect_mcp_invisible_unicode",
     "detect_mcp_invisible_unicode(server_url='https://mcp.example.com/mcp')"),
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
     "# idpi_illegal_utf8_normalization_2026"),
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
    # msfrpcd fast-daemon path — distinct transport from the msfconsole
    # subprocess tools above. Route here when the operator has msfrpcd running
    # or needs high-volume module lookups (batch CVE checks).
    (["msfrpc", "msfrpcd", "msf daemon", "fast msf", "batch msf",
      "msf rpc", "high volume msf"], "msfrpc_module_search",
     "msfrpc_login(password='...') then msfrpc_module_search(query='log4shell')  "
     "# needs msfrpcd running; ~10x faster than msfconsole subprocess for volume"),
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
]
