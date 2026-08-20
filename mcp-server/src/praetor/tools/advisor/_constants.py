"""Static lookup tables shared across advisor tools.

Lifted out of the per-call closures so the dicts allocate once at import.
"""

# Tech stack -> prioritized vulnerability categories
TECH_PRIORITIES = {
    "php": ["sqli", "lfi", "file_upload", "ssti", "command_injection", "xxe", "ssrf", "deserialization"],
    "java": ["deserialization", "xxe", "ssti", "sqli", "ssrf", "path_traversal", "command_injection", "log4shell", "spring4shell"],
    "python": ["ssti", "command_injection", "ssrf", "sqli", "deserialization", "path_traversal"],
    "flask": ["ssti", "command_injection", "ssrf", "sqli", "info_disclosure", "path_traversal"],
    "fastapi": ["ssti", "mass_assignment", "ssrf", "idor", "auth_bypass", "graphql", "info_disclosure"],
    "bottle": ["ssti", "command_injection", "path_traversal", "info_disclosure"],
    "tornado": ["ssti", "ssrf", "command_injection", "auth_bypass"],
    "django": ["ssti", "sqli", "idor", "ssrf", "path_traversal", "xss", "mass_assignment", "secret_key_leak"],
    "node": ["ssti", "ssrf", "command_injection", "prototype_pollution", "path_traversal", "sqli", "deserialization"],
    "express": ["ssti", "ssrf", "prototype_pollution", "path_traversal", "sqli", "xss", "options_pollution"],
    "nextjs": ["ssrf", "prototype_pollution", "open_redirect", "rsc_disclosure", "xss"],
    "nestjs": ["mass_assignment", "ssrf", "auth_bypass", "graphql", "idor"],
    "asp.net": ["deserialization", "sqli", "path_traversal", "xxe", "ssrf", "xss", "viewstate"],
    ".net": ["deserialization", "sqli", "path_traversal", "xxe", "ssrf", "xss", "viewstate"],
    "ruby": ["ssti", "command_injection", "deserialization", "sqli", "ssrf", "xss"],
    "rails": ["mass_assignment", "ssti", "sqli", "command_injection", "idor", "ssrf", "secret_key_leak"],
    "laravel": ["sqli", "deserialization", "ssti", "mass_assignment", "path_traversal", "file_upload", "blade_injection"],
    "symfony": ["ssti", "sqli", "deserialization", "secret_leak", "path_traversal"],
    "spring": ["deserialization", "ssti", "xxe", "sqli", "ssrf", "path_traversal", "spring4shell", "log4shell"],
    "spring-boot": ["deserialization", "actuator_exposure", "ssrf", "ssti", "log4shell"],
    "angular": ["xss", "ssti", "prototype_pollution", "cors", "open_redirect", "csrf"],
    "react": ["xss", "ssrf", "cors", "prototype_pollution", "open_redirect", "rsc_disclosure"],
    "vue": ["xss", "ssti", "prototype_pollution", "open_redirect"],
    "svelte": ["xss", "open_redirect", "ssrf"],
    "wordpress": ["sqli", "xss", "file_upload", "lfi", "auth_bypass", "ssrf", "xmlrpc", "rest_user_enum"],
    "drupal": ["sqli", "xss", "file_upload", "lfi", "auth_bypass", "drupalgeddon"],
    "joomla": ["sqli", "xss", "file_upload", "lfi", "auth_bypass"],
    "magento": ["sqli", "xss", "deserialization", "xxe", "ssrf", "auth_bypass"],
    "shopify": ["graphql", "open_redirect", "auth_bypass", "ssrf", "idor"],
    "graphql": ["graphql", "idor", "sqli", "injection", "auth_bypass", "info_disclosure", "alias_login_brute"],
    "api": ["idor", "auth_bypass", "mass_assignment", "sqli", "ssrf", "rate_limit_missing", "graphql"],
    "go": ["ssrf", "ssti", "path_traversal", "auth_bypass", "rce"],
    "fiber": ["ssrf", "path_traversal", "auth_bypass"],
    "echo": ["ssrf", "path_traversal", "auth_bypass"],
    "default": ["xss", "sqli", "ssrf", "idor", "auth_bypass", "ssti", "path_traversal"],
}

# Parameter name -> likely vulnerability
PARAM_VULN_MAP = {
    "id": "idor", "uid": "idor", "user_id": "idor", "account_id": "idor", "order_id": "idor",
    "search": "xss", "q": "xss", "query": "xss", "name": "xss", "comment": "xss", "message": "xss",
    "url": "ssrf", "redirect": "open_redirect", "next": "open_redirect", "return": "open_redirect",
    "callback": "ssrf", "webhook": "ssrf", "target": "ssrf", "uri": "ssrf",
    "file": "lfi", "path": "lfi", "page": "lfi", "template": "ssti", "include": "lfi",
    "email": "sqli", "username": "sqli", "login": "sqli", "sort": "sqli", "order": "sqli",
    "cmd": "command_injection", "exec": "command_injection", "command": "command_injection",
    "lang": "lfi", "locale": "lfi", "dir": "path_traversal", "folder": "path_traversal",
}

# Phase definitions (used by hunt_plan / next_action)
PHASES = {
    "recon": {
        "description": "Map attack surface — discover endpoints, tech stack, parameters",
        "tools": [
            ("browser_crawl", "Crawl target through Burp proxy to populate history"),
            ("get_proxy_history", "Review captured traffic"),
            ("detect_tech_stack", "Identify server tech, frameworks, security headers"),
            ("smart_analyze", "Combined analysis on key endpoints"),
            ("extract_js_secrets", "Check JS files for leaked secrets"),
        ],
    },
    "probe": {
        "description": "Test high-risk parameters with knowledge-driven probes",
        "tools": [
            ("auto_probe", "Knowledge-driven probing across vuln categories"),
            ("probe_endpoint", "Targeted testing on specific params"),
            ("test_cors", "Check CORS misconfig"),
            ("test_jwt", "Analyze JWT tokens if present"),
            ("discover_common_files", "Check for .git, .env, debug endpoints"),
        ],
    },
    "exploit": {
        "description": "Targeted attacks on confirmed attack surface",
        "tools": [
            ("fuzz_parameter", "Smart fuzzing with auto-generated payloads"),
            ("test_auth_matrix", "IDOR detection across auth states"),
            ("test_race_condition", "TOCTOU on state-changing endpoints"),
            ("auto_collaborator_test", "Blind testing with OOB callbacks"),
        ],
    },
    "verify": {
        "description": "Verify findings with reproducible evidence",
        "tools": [
            ("session_request", "Reproduce finding with clean request"),
            ("compare_auth_states", "Confirm IDOR with auth comparison"),
            ("get_response_hash", "Check response consistency"),
        ],
    },
}
