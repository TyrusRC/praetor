"""SAST route-pattern data + extraction/dedupe helpers for sast_handoff."""

from __future__ import annotations

import re
from pathlib import Path


_SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".rb"}
_SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
    "dist", "build", "vendor", ".next", "target", "site-packages",
}


# Rule-ID substrings → Praetor vuln_type. Order matters: first match wins.
_RULE_VULN_MAP: list[tuple[str, str, int]] = [
    # (substring, vuln_type, base_risk_score)
    ("sql-injection", "sqli", 9),
    ("sqli", "sqli", 9),
    ("ssrf", "ssrf", 9),
    ("ssti", "ssti", 9),
    ("server-side-template", "ssti", 9),
    ("xss", "xss", 7),
    ("cross-site-script", "xss", 7),
    ("command-injection", "rce", 10),
    ("os-command", "rce", 10),
    ("rce", "rce", 10),
    ("path-traversal", "lfi", 8),
    ("lfi", "lfi", 8),
    ("file-inclusion", "lfi", 8),
    ("xxe", "xxe", 8),
    ("xml-external-entity", "xxe", 8),
    ("deserialization", "deserialization", 9),
    ("unsafe-deserial", "deserialization", 9),
    ("pickle", "deserialization", 9),
    ("open-redirect", "open_redirect", 5),
    ("unvalidated-redirect", "open_redirect", 5),
    ("hardcoded-secret", "secret_disclosure", 7),
    ("hardcoded-credential", "secret_disclosure", 7),
    ("hardcoded-password", "secret_disclosure", 7),
    ("jwt", "jwt", 7),
    ("weak-crypto", "weak_crypto", 5),
    ("weak-hash", "weak_crypto", 5),
    ("md5", "weak_crypto", 4),
    ("insecure-cookie", "insecure_cookie", 4),
    ("csrf", "csrf", 5),
    ("cors", "cors_misconfig", 5),
    ("ldap-injection", "ldap_injection", 8),
    ("nosql-injection", "nosql_injection", 8),
    ("prototype-pollution", "prototype_pollution", 8),
    ("regex-dos", "redos", 6),
    ("redos", "redos", 6),
    ("mass-assignment", "mass_assignment", 7),
    ("graphql", "graphql", 7),
]


# Route decorator regexes per framework. Each yields (method, path) when matched.
_ROUTE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Flask / Quart
    ("flask", re.compile(
        r'@(?:[\w.]+\.)?route\s*\(\s*["\']([^"\']+)["\']'
        r'(?:[^)]*?methods\s*=\s*\[([^\]]+)\])?',
        re.I | re.S,
    )),
    # FastAPI / Starlette / Sanic
    ("fastapi", re.compile(
        r'@(?:[\w.]+\.)?(get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\']+)["\']',
        re.I,
    )),
    # Express / Koa / Fastify (JS)
    ("express", re.compile(
        r'\b(?:app|router|fastify)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*["\']([^"\']+)["\']',
        re.I,
    )),
    # Spring (Java/Kotlin)
    ("spring_method", re.compile(
        r'@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*["\']([^"\']+)["\']',
    )),
    # Rails (config/routes.rb)
    ("rails", re.compile(
        r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
        re.I,
    )),
]


def _classify_rule(rule_id: str) -> tuple[str, int]:
    rid = rule_id.lower()
    for needle, vtype, base in _RULE_VULN_MAP:
        if needle in rid:
            return vtype, base
    return "generic_sink", 3


def _route_from_match(framework: str, m: re.Match[str]) -> dict[str, str]:
    """Turn a single _ROUTE_PATTERNS match into a {framework, method, path} dict.

    Shared by the finding-walkback (SAST handoff) and the standalone source
    route inventory so the per-framework group ordering lives in one place.
    """
    if framework == "flask":
        path = m.group(1)
        methods_raw = (m.group(2) or "").upper()
        method = "GET"
        for verb in ("POST", "PUT", "PATCH", "DELETE"):
            if verb in methods_raw:
                method = verb
                break
        return {"framework": framework, "method": method, "path": path}
    if framework == "fastapi":
        return {"framework": framework, "method": m.group(1).upper(), "path": m.group(2)}
    if framework == "express":
        method = m.group(1).upper()
        if method == "ALL":
            method = "ANY"
        return {"framework": framework, "method": method, "path": m.group(2)}
    if framework == "spring_method":
        verb = m.group(1).upper()
        method = "GET" if verb == "REQUEST" else verb.upper()
        return {"framework": "spring", "method": method, "path": m.group(2)}
    if framework == "rails":
        return {"framework": framework, "method": m.group(1).upper(), "path": m.group(2)}
    return {}


def _walk_back_for_route(file_path: Path, line: int, lookback: int = 30) -> dict[str, str]:
    """Read up to `lookback` lines before `line` looking for a route decorator.

    Returns {method, path, framework} or empty dict if none found.
    """
    if not file_path.exists() or not file_path.is_file():
        return {}
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    start = max(0, line - lookback)
    end = min(len(lines), line)
    snippet = "\n".join(lines[start:end])
    for framework, pattern in _ROUTE_PATTERNS:
        m = pattern.search(snippet)
        if not m:
            continue
        route = _route_from_match(framework, m)
        if route:
            return route
    # Next.js / Remix filesystem route fallback.
    path_str = str(file_path)
    if "/app/" in path_str and path_str.endswith(("route.ts", "route.js", "route.tsx", "route.jsx")):
        seg = path_str.split("/app/", 1)[1].rsplit("/", 1)[0]
        return {"framework": "nextjs_app_router", "method": "ANY", "path": "/" + seg}
    if "/pages/api/" in path_str:
        api_path = path_str.split("/pages/api/", 1)[1].rsplit(".", 1)[0]
        return {"framework": "nextjs_pages_api", "method": "ANY", "path": "/api/" + api_path}
    return {}



def _dedupe_routes(routes: list[dict[str, str]]) -> list[dict[str, str]]:
    """Collapse routes by (METHOD, path); keep the first source seen."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for r in routes:
        key = (r["method"].upper(), r["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out
