"""Pure proxy-history noise analysis. No client calls, no side effects."""

from urllib.parse import urlparse

_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".webp")


def _path(entry: dict) -> str:
    url = entry.get("url") or entry.get("path") or ""
    try:
        return urlparse(url).path or url
    except ValueError:
        return url


def _is_static(entry: dict) -> bool:
    p = _path(entry).lower()
    if p.endswith(_STATIC_EXT):
        return True
    mime = (entry.get("mime_type") or entry.get("mime") or "").lower()
    return any(m in mime for m in ("image", "font", "css", "javascript"))


def analyze_noise(history: list[dict], scope_hosts: set[str] | None = None) -> dict:
    total = len(history)
    static = sum(1 for e in history if _is_static(e))
    in_scope = out_scope = 0
    host_counts: dict[str, int] = {}
    path_counts: dict[tuple, int] = {}
    for e in history:
        host = e.get("host") or urlparse(e.get("url", "")).netloc
        host_counts[host] = host_counts.get(host, 0) + 1
        if scope_hosts is not None:
            if any(host == h or host.endswith("." + h) for h in scope_hosts):
                in_scope += 1
            else:
                out_scope += 1
        key = (e.get("method", "GET"), _path(e))
        path_counts[key] = path_counts.get(key, 0) + 1

    dup = [{"method": k[0], "path": k[1], "count": c}
           for k, c in path_counts.items() if c >= 2]
    dup.sort(key=lambda d: -d["count"])
    top_hosts = sorted(host_counts.items(), key=lambda kv: -kv[1])[:5]
    static_pct = round(100 * static / total, 1) if total else 0.0

    recs = []
    if static_pct >= 30:
        recs.append(f"{static_pct}% static assets — route recon/volume off-proxy "
                    "(Logger-only tools) and exclude static in configure_scope.")
    if out_scope:
        recs.append(f"{out_scope} out-of-scope entries — tighten configure_scope; "
                    "Burp cannot delete history, so scope at capture time.")
    if dup:
        recs.append(f"{len(dup)} duplicated request clusters — run volume via "
                    "concurrent_requests/intruder, not repeated proxied calls.")
    if not recs:
        recs.append("History is lean — no action needed.")

    return {"total": total, "in_scope": in_scope, "out_of_scope": out_scope,
            "static_assets": static, "static_pct": static_pct,
            "duplicate_clusters": dup[:10], "top_noisy_hosts": top_hosts,
            "recommendations": recs}
