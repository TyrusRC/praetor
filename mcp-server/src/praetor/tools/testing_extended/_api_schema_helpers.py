"""Postman/OpenAPI parsing helpers + keyword maps (extracted from api_schema.py)"""


import json
import re

from mcp.server.fastmcp import FastMCP

from praetor import client

_INTERESTING_KEYWORDS = {
    "auth": ["login", "signin", "signup", "register", "auth", "oauth", "token", "password", "reset", "verify"],
    "file": ["upload", "download", "file", "attachment", "import", "export", "image", "media"],
    "admin": ["admin", "manage", "dashboard", "config", "setting", "internal"],
    "user_crud": ["user", "account", "profile", "member"],
    "payment": ["payment", "billing", "subscription", "checkout", "order", "invoice", "charge", "refund"],
}


_POSTMAN_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_\-.]+)\s*\}\}")


def _postman_substitute(text: str, env: dict[str, str]) -> str:
    """Replace {{var}} tokens using env dict; unknown vars left intact for inspection."""
    if not text or "{{" not in text:
        return text
    def repl(m):
        key = m.group(1)
        return env.get(key, m.group(0))  # keep literal if unset
    return _POSTMAN_VAR_RE.sub(repl, text)


def _postman_env_to_dict(env_obj) -> dict[str, str]:
    """Postman environment JSON has {values: [{key,value,enabled}]} OR a flat dict."""
    if not env_obj:
        return {}
    if isinstance(env_obj, dict) and "values" in env_obj:
        out = {}
        for v in env_obj.get("values", []):
            if isinstance(v, dict) and v.get("enabled", True) and "key" in v:
                out[v["key"]] = str(v.get("value", ""))
        return out
    if isinstance(env_obj, dict):
        return {k: str(v) for k, v in env_obj.items()}
    return {}


def _is_postman(spec: dict) -> bool:
    """Detect Postman v2.x collection."""
    info = spec.get("info", {})
    if isinstance(info, dict):
        schema = info.get("schema", "")
        if "postman.com/json/collection" in schema or "getpostman.com/json/collection" in schema:
            return True
    return "item" in spec and isinstance(spec.get("item"), list)


def _postman_walk_items(items, env: dict[str, str], parent_path: str = "") -> list[dict]:
    """Recursively walk Postman item tree; return list of endpoints."""
    endpoints = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = it.get("name", "")
        # Folder
        if "item" in it and isinstance(it["item"], list):
            sub_path = f"{parent_path}/{name}" if parent_path else name
            endpoints.extend(_postman_walk_items(it["item"], env, sub_path))
            continue
        # Request
        req = it.get("request")
        if not isinstance(req, dict):
            continue
        method = req.get("method", "GET")
        url_raw = req.get("url", "")
        if isinstance(url_raw, dict):
            # url object — prefer .raw, else build from path parts
            url_str = url_raw.get("raw") or "/" + "/".join(url_raw.get("path", []) or [])
            if not url_raw.get("raw"):
                host = url_raw.get("host")
                if isinstance(host, list):
                    host = ".".join(host)
                if host:
                    proto = url_raw.get("protocol", "https")
                    url_str = f"{proto}://{host}{url_str}"
        else:
            url_str = str(url_raw)
        url_str = _postman_substitute(url_str, env)

        # Headers
        headers_list = req.get("header", []) or []
        headers = {}
        for h in headers_list:
            if isinstance(h, dict) and not h.get("disabled", False):
                headers[h.get("key", "")] = _postman_substitute(str(h.get("value", "")), env)

        # Body
        body_obj = req.get("body", {})
        body_str = ""
        body_mode = ""
        params = []
        if isinstance(body_obj, dict):
            body_mode = body_obj.get("mode", "")
            if body_mode == "raw":
                body_str = _postman_substitute(body_obj.get("raw", ""), env)
            elif body_mode == "urlencoded":
                for u in body_obj.get("urlencoded", []) or []:
                    if isinstance(u, dict) and not u.get("disabled", False):
                        params.append({
                            "name": u.get("key", "?"), "in": "body",
                            "required": False, "type": "string",
                        })
            elif body_mode == "formdata":
                for u in body_obj.get("formdata", []) or []:
                    if isinstance(u, dict) and not u.get("disabled", False):
                        params.append({
                            "name": u.get("key", "?"), "in": "form",
                            "required": False, "type": "file" if u.get("type") == "file" else "string",
                        })
            elif body_mode == "graphql":
                gql = body_obj.get("graphql", {})
                body_str = _postman_substitute(json.dumps(gql), env)

        # Query parameters from URL
        if isinstance(url_raw, dict):
            for q in url_raw.get("query", []) or []:
                if isinstance(q, dict) and not q.get("disabled", False):
                    params.append({
                        "name": q.get("key", "?"), "in": "query",
                        "required": False, "type": "string",
                    })

        # If body is raw JSON, harvest top-level keys as params for vuln-mapping
        if body_str and body_str.strip().startswith("{"):
            try:
                jb = json.loads(body_str)
                if isinstance(jb, dict):
                    for k in jb.keys():
                        params.append({"name": k, "in": "body-json", "required": False, "type": type(jb[k]).__name__})
            except json.JSONDecodeError:
                pass

        endpoints.append({
            "name": f"{parent_path}/{name}" if parent_path else name,
            "method": method,
            "url": url_str,
            "headers": headers,
            "params": params,
            "body_mode": body_mode,
            "body": body_str[:300],
        })
    return endpoints

_PARAM_VULN_MAP = {
    "id": "IDOR", "user_id": "IDOR", "account_id": "IDOR", "uid": "IDOR", "pid": "IDOR",
    "search": "XSS", "q": "XSS", "query": "XSS", "name": "XSS", "comment": "XSS",
    "file": "LFI", "filename": "LFI", "path": "LFI", "filepath": "LFI", "template": "SSTI",
    "url": "SSRF", "uri": "SSRF", "href": "SSRF", "callback": "SSRF", "redirect": "Open Redirect",
    "redirect_url": "Open Redirect", "next": "Open Redirect", "return_url": "Open Redirect",
    "cmd": "Command Injection", "command": "Command Injection", "exec": "Command Injection",
    "email": "Injection", "sort": "SQLi", "order": "SQLi", "filter": "SQLi/NoSQLi",
}
