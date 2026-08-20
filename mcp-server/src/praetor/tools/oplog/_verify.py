"""Reconcile the operation ledger against Burp's own history.

The ledger says what left this process. Burp's history says what Burp saw. The
interesting output is where the two disagree:

  - a logged operation with no Burp entry means a claimed request produced no
    traffic Burp can show — the shape of a citation that cannot be backed up;
  - a Burp entry with no logged operation means traffic arrived by some other
    route (a browser, an external tool, a hand-run script, or a server-side
    scan tool such as auto_probe/scan_url whose individual probes the ledger
    does not enumerate) and cannot be attributed to a single direct-send call.

Evidence integrity does not depend on this reconciliation: every cited
history_index is validated against proxy history by EvidenceMatch (Java) at
save time regardless of whether the send passed through the Python ledger.

Neither direction is automatically a defect; both are things a report should
never paper over.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from praetor import client

from ._store import read_entries


def _norm(url: str) -> str:
    """Compare on scheme-less host+path+query — Burp and the ledger differ on
    encoding and default ports, and neither difference means anything here."""
    if not url:
        return ""
    try:
        p = urlsplit(url)
    except ValueError:
        return url.lower()
    host = (p.netloc or "").lower()
    for suffix in (":80", ":443"):
        if host.endswith(suffix):
            host = host[: -len(suffix)]
    return f"{host}{p.path}?{p.query}".rstrip("?").lower()


async def reconcile(host: str = "", limit: int = 500) -> dict:
    """Match ledger operations against Burp history entries for `host`."""
    ops = [e for e in read_entries(host=host, sent_only=True) if e.get("outcome") == "ok"]

    params: dict = {"limit": max(limit, 1)}
    if host:
        params["host"] = host
    data = await client.get("/api/proxy/history", params=params)
    if "error" in data:
        return {"error": data["error"]}

    # /api/proxy/history returns the list under "items" (ProxyHandler). The
    # other keys are accepted so a change on the Java side degrades to empty
    # rather than crashing — but "items" is the real one, and reading the wrong
    # key is exactly what made reconcile report every real send as UNBACKED.
    history = data.get("items", data.get("history", data.get("entries", []))) or []
    hist_by_url: dict[str, list[dict]] = {}
    for h in history:
        if not isinstance(h, dict):
            continue
        hist_by_url.setdefault(_norm(str(h.get("url", ""))), []).append(h)

    matched: list[dict] = []
    unmatched_ops: list[dict] = []
    claimed: set[int] = set()

    for op in ops:
        key = _norm(str(op.get("url", "")))
        candidates = hist_by_url.get(key, [])
        hit = next((h for h in candidates if id(h) not in claimed), None)
        if hit is None:
            unmatched_ops.append(op)
            continue
        claimed.add(id(hit))
        matched.append({
            "seq": op.get("seq"),
            "tool": op.get("tool"),
            "url": op.get("url"),
            "burp_index": hit.get("index"),
            "ledger_status": op.get("status"),
            "burp_status": hit.get("status_code", hit.get("status")),
        })

    unmatched_history = [
        {"index": h.get("index"), "method": h.get("method"), "url": h.get("url")}
        for lst in hist_by_url.values() for h in lst if id(h) not in claimed
    ]

    # A matched pair whose status codes disagree is worse than an unmatched one:
    # it means a citation resolves, but to a different outcome than was claimed.
    status_conflicts = [
        m for m in matched
        if m["ledger_status"] is not None and m["burp_status"] is not None
        and int(m["ledger_status"]) != int(m["burp_status"])
    ]

    return {
        "host": host or "(all)",
        "ledger_operations": len(ops),
        "burp_entries": len(history),
        "matched": len(matched),
        "unmatched_operations": unmatched_ops,
        "unmatched_history": unmatched_history[:50],
        "status_conflicts": status_conflicts,
        "matches": matched,
    }
