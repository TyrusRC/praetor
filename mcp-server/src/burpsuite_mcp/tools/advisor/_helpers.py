"""Pure helpers used across advisor sub-tools."""


def detect_tech_from_headers(headers: list[dict]) -> list[str]:
    """Extract tech hints from response headers."""
    techs = []
    for h in headers:
        name = h.get("name", "").lower()
        value = h.get("value", "").lower()
        if name == "x-powered-by":
            if "php" in value: techs.append("php")
            if "express" in value: techs.append("express")
            if "asp.net" in value: techs.append("asp.net")
        if name == "server":
            if "apache" in value: techs.append("php")
            # nginx is a generic reverse proxy — don't assume backend tech
            if "gunicorn" in value or "uvicorn" in value: techs.append("python")
        if "set-cookie" in name:
            if "phpsessid" in value: techs.append("php")
            if "jsessionid" in value: techs.append("java")
            if "connect.sid" in value: techs.append("express")
            if "csrftoken" in value: techs.append("django")
            if "laravel_session" in value: techs.append("laravel")
    return list(set(techs))


def prioritize_params(params: list[dict]) -> list[dict]:
    """Score and sort parameters by attack priority."""
    from burpsuite_mcp.tools.advisor._constants import PARAM_VULN_MAP

    scored = []
    for p in params:
        name = p.get("name", "").lower()
        vuln = PARAM_VULN_MAP.get(name)
        score = 3 if vuln else 1
        if p.get("reflected"):
            score += 2
        scored.append({**p, "priority_score": score, "likely_vuln": vuln or "unknown"})
    scored.sort(key=lambda x: x["priority_score"], reverse=True)
    return scored


def vuln_root(v: str) -> str:
    """Trim common suffixes so sqli == sqli_blind == sqli_time for dedup."""
    v = (v or "").lower().strip()
    for sep in ("_blind", "_time", "_boolean", "_error", "_oob",
                "_reflected", "_stored", "_dom", "_second_order"):
        if v.endswith(sep):
            v = v[: -len(sep)]
    return v
