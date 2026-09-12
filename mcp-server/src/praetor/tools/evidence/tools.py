"""Evidence-flow tools: one-call curation + history-noise audit.
Burp history is read-only (Montoya) — these curate and audit, never delete."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.notes._helpers import (
    _load_findings_file, _safe_findings_path, _write_findings_file,
)

from . import _audit, _curate

import json
import time
from pathlib import Path

from praetor.tools.intel._internals import _intel_path


async def snapshot_and_rotate(domain: str, scanner_limit: int = 500,
                              sitemap_limit: int = 2000) -> dict:
    """Preserve the Burp-side signal to `.burp-intel/<domain>/snapshots/<ts>/` so
    the bloated Burp project can be safely discarded / rotated.

    Findings, coverage, endpoints and target intel already live on disk under
    `.burp-intel/<domain>/` and survive a new Burp project automatically. What
    is LOST when you start a fresh project is the Burp-held state: the sitemap
    and the scanner issues. This snapshots those (plus a proxy-history size
    reading) and writes a manifest, then tells you it is safe to rotate.

    Montoya has no "new project" API, so the rotation itself is a one-click
    operator action (Burp: File → New project). This tool makes it lossless.

    Args:
        domain: target domain whose intel dir receives the snapshot.
        scanner_limit: max scanner issues to snapshot.
        sitemap_limit: max sitemap entries to snapshot.
    """
    if not domain:
        return {"error": "domain required"}
    ts = time.strftime("%Y%m%d-%H%M%S")
    snap_dir = _intel_path(domain) / "snapshots" / ts
    try:
        snap_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create snapshot dir: {exc}"}

    written: dict[str, int] = {}

    scanner = await client.get("/api/scanner/findings", params={"limit": scanner_limit})
    issues = scanner.get("items", scanner.get("findings", scanner)) if isinstance(scanner, dict) else scanner
    if isinstance(issues, list):
        (snap_dir / "scanner_findings.json").write_text(json.dumps(issues, indent=2), encoding="utf-8")
        written["scanner_findings"] = len(issues)

    sm = await client.get("/api/sitemap", params={"limit": sitemap_limit})
    sm_entries = sm.get("items", sm.get("sitemap", sm)) if isinstance(sm, dict) else sm
    if isinstance(sm_entries, list):
        (snap_dir / "sitemap.json").write_text(json.dumps(sm_entries, indent=2), encoding="utf-8")
        written["sitemap_entries"] = len(sm_entries)

    count = await client.get("/api/proxy/count")
    proxy_count = count.get("count") if isinstance(count, dict) else None
    (snap_dir / "proxy_summary.json").write_text(
        json.dumps({"proxy_history_count": proxy_count, "captured_at": ts}, indent=2), encoding="utf-8")

    # Which on-disk intel survives rotation untouched (reference, don't copy).
    survives = [p.name for p in _intel_path(domain).glob("*.json")]
    manifest = {
        "domain": domain, "snapshot": str(snap_dir), "created": ts,
        "burp_state_snapshotted": written,
        "proxy_history_count": proxy_count,
        "survives_rotation_on_disk": sorted(survives),
    }
    (snap_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    manifest["note"] = (
        "Safe to rotate. In Burp: File → New project (or open a fresh temp project) — "
        "this discards the bloated proxy history + issues. Your findings.json, coverage, "
        "endpoints and intel under .burp-intel survive automatically; this snapshot preserves "
        "the Burp-side sitemap + scanner issues for reference. Re-run recon on the fresh project "
        "only for the surface you still need."
    )
    return manifest


async def curate_evidence(finding_id: str, index: int, domain: str,
                          color: str = "RED", comment: str = "",
                          endpoint: str = "") -> str:
    """Curate one evidence request in a single call: annotate it in Burp,
    send it to the Organizer, and record it as the finding's canonical evidence
    index (Rule 18). Use after a finding is confirmed."""
    ann = await client.post("/api/annotations/set", json={
        "index": index, "color": color,
        "comment": comment or f"{finding_id} | evidence", "endpoint": endpoint})
    if isinstance(ann, dict) and "error" in ann:
        return f"Annotation failed: {ann['error']}"
    org = await client.post("/api/organizer/send", json={"index": index})
    org_note = org.get("error", "sent") if isinstance(org, dict) else "sent"

    path = _safe_findings_path(domain)
    findings = _load_findings_file(path)
    findings, msg = _curate.apply_curation(findings, finding_id, index, color)
    if "not found" not in msg:
        _write_findings_file(path, findings)
    return f"{msg} Annotated {color} + organizer:{org_note}."


async def audit_history_noise(domain: str = "", limit: int = 1000) -> dict:
    """Report proxy-history composition (in-scope / static / duplicates / noisy
    hosts) and recommendations. Burp cannot delete history — this guides
    capture-time scope + off-proxy routing to keep the .burp project lean."""
    data = await client.get("/api/proxy/history", params={"limit": limit})
    if isinstance(data, dict) and "error" in data:
        return {"error": data["error"]}
    entries = data.get("items", data.get("history", data)) if isinstance(data, dict) else data
    scope = {domain} if domain else None
    return _audit.analyze_noise(entries if isinstance(entries, list) else [], scope)


async def verify_capture_hygiene(domain: str = "", baseline: dict | None = None,
                                 limit: int = 5000) -> dict:
    """Measure whether set_capture_hygiene is actually working — the noise rate of
    NEW capture, not assumed.

    Burp cannot delete old history, so total-history noise never drops; the fix
    only affects newly-recorded traffic. This reads the cumulative static /
    out-of-scope counts, and when given a prior `baseline` computes the DELTA —
    the composition of just the traffic captured since — so you see whether new
    entries are clean.

    Workflow:
      1. base = verify_capture_hygiene(domain)          # snapshot BEFORE
      2. set_capture_hygiene()                            # apply
      3. browser_crawl(...) / normal testing             # generate traffic
      4. verify_capture_hygiene(domain, baseline=base["current"])   # measure

    Args:
        domain: restrict to one host (empty = all history).
        baseline: the `current` object from a prior call, to diff against.
        limit: max history entries to read for the composition counts.
    """
    # Fetch all history; scope filtering is done in analyze_noise (the server-side
    # host filter is exact-match and entries carry host in the url, not a field).
    data = await client.get("/api/proxy/history", params={"limit": limit})
    if isinstance(data, dict) and "error" in data:
        return {"error": data["error"]}
    entries = data.get("items", data.get("history", data)) if isinstance(data, dict) else data
    scope = {domain} if domain else None
    snap = _audit.analyze_noise(entries if isinstance(entries, list) else [], scope)

    current = {
        "proxy_count": snap["total"],
        "static": snap["static_assets"],
        "out_of_scope": snap["out_of_scope"],
    }
    out: dict = {
        "domain": domain or "(all)",
        "current": current,
        "static_pct": snap["static_pct"],
        "top_noisy_hosts": snap.get("top_noisy_hosts", [])[:5],
    }

    if baseline:
        d_total = current["proxy_count"] - int(baseline.get("proxy_count", 0))
        d_static = current["static"] - int(baseline.get("static", 0))
        d_oos = current["out_of_scope"] - int(baseline.get("out_of_scope", 0))
        if d_total > 0:
            new_static_pct = round(100 * d_static / d_total, 1)
            new_oos_pct = round(100 * d_oos / d_total, 1)
            working = new_static_pct < 5.0 and d_oos == 0
            out["delta"] = {
                "new_entries": d_total, "new_static": d_static, "new_out_of_scope": d_oos,
                "new_static_pct": new_static_pct, "new_out_of_scope_pct": new_oos_pct,
            }
            out["verdict"] = (
                "WORKING — new traffic is clean (static/out-of-scope near zero)" if working
                else f"NOT EFFECTIVE for CAPTURE — {new_static_pct}% of new traffic is static/media, "
                     f"{new_oos_pct}% out-of-scope, still RECORDED. Burp records everything regardless of "
                     "the display filter (set_capture_hygiene only cleans the VIEW), so shrink the .burp file "
                     "with snapshot_and_rotate + a fresh project. NOTE: browser crawls always pull static "
                     "sub-resources — this high % is expected for browser traffic; API/tool traffic stays clean."
            )
        elif d_total < 0:
            out["verdict"] = "history shrank vs baseline — a project rotation happened; re-baseline."
        else:
            out["verdict"] = "no new traffic since baseline — generate some (browser_crawl) then re-run."
    else:
        out["note"] = ("Baseline captured. Now: set_capture_hygiene() → generate traffic → "
                       "verify_capture_hygiene(domain, baseline=<this 'current'>).")
    return out


def register(mcp: FastMCP) -> None:
    mcp.tool()(curate_evidence)
    mcp.tool()(audit_history_noise)
    mcp.tool()(snapshot_and_rotate)
    mcp.tool()(verify_capture_hygiene)
