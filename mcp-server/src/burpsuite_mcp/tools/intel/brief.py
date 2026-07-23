"""target_brief — one-call situational orientation for the agent (Spec E).

Fuses the per-domain intel files into a single token-lean map so Claude can
"quick understand context, quick query, quick action" without firing four
separate loads. Read-only. Reuses the canonical files under .burp-intel/<domain>/.

Answers three questions in one call:
  - CONTEXT   — tech stack, auth model, scope note, findings posture.
  - QUERY     — copy-paste follow-up calls (already field-projected / lean).
  - ACTION    — deterministic next-move hints from the current state.

Returns a compact dict (NOT indent-pretty — this is machine-consumed).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._internals import _intel_path


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _read(path) -> dict:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def build_brief(domain: str, max_items: int = 8) -> dict[str, Any]:
    """Pure builder — assembles the orientation dict from disk. Testable."""
    d = _intel_path(domain)
    if not d.exists():
        return {
            "domain": domain,
            "exists": False,
            "directive": (
                "NEW TARGET — no intel on disk. Run recon before testing "
                "(browser_crawl -> full_recon -> discover_attack_surface), "
                "then save_target_intel. (Rule 20a)"
            ),
        }

    profile = _read(d / "profile.json")
    endpoints = _read(d / "endpoints.json").get("endpoints", []) or []
    coverage = _read(d / "coverage.json")
    cov_entries = coverage.get("entries", []) or []
    findings = _read(d / "findings.json").get("findings", []) or []

    by_status: dict[str, int] = {}
    for f in findings:
        s = f.get("status", "open")
        by_status[s] = by_status.get(s, 0) + 1

    ranked = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5),
                       0 if f.get("status") == "confirmed" else 1),
    )
    top = [
        {k: f.get(k) for k in ("id", "title", "severity", "status", "endpoint")
         if k in f}
        for f in ranked[:max_items]
    ]

    # freshness
    stale_hint = None
    fresh_path = d / "fingerprint.json"
    last_mod = None
    if fresh_path.exists():
        last_mod = datetime.fromtimestamp(
            fresh_path.stat().st_mtime, tz=timezone.utc).isoformat()

    # deterministic next-action hints
    actions: list[str] = []
    suspected = by_status.get("suspected", 0)
    confirmed = by_status.get("confirmed", 0)
    if suspected:
        actions.append(f"verify {suspected} suspected finding(s) — verify-finding.md")
    if len(endpoints) > len(cov_entries):
        actions.append(
            f"coverage gap: {len(endpoints)} endpoints known vs {len(cov_entries)} "
            "covered tuples — next_untested_targets / auto_probe")
    if confirmed:
        actions.append(
            f"chain {confirmed} confirmed finding(s) for escalation — chain-findings.md")
    if not findings and endpoints:
        actions.append(
            "surface mapped, no findings yet — auto_probe top-risk params")
    if not endpoints:
        actions.append("no endpoints recorded — discover_attack_surface / browser_crawl")

    return {
        "domain": domain,
        "exists": True,
        "context": {
            "tech_stack": profile.get("tech_stack", []),
            "auth_model": profile.get("auth_model") or profile.get("auth") or "unknown",
            "scope_note": profile.get("scope_note") or profile.get("scope") or "",
            "edition": profile.get("burp_edition") or profile.get("edition") or "",
        },
        "posture": {
            "endpoints_known": len(endpoints),
            "coverage_tuples": len(cov_entries),
            "knowledge_version": coverage.get("knowledge_version", "?"),
            "findings": {**by_status, "total": len(findings)},
        },
        "top_findings": top,
        "next_actions": actions or ["intel present; pick a class and auto_probe"],
        "freshness": {"last_modified": last_mod, "stale_hint": stale_hint},
        "quick_queries": [
            f"load_target_intel('{domain}','findings',"
            "fields='id,title,severity,status,endpoint,vuln_type',"
            "status_filter='confirmed,suspected')",
            f"coverage_summary('{domain}')",
            f"next_untested_targets('{domain}')",
            f"check_target_freshness('{domain}', session='')",
        ],
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def target_brief(domain: str, max_items: int = 8) -> dict:
        """One-call situational orientation for a target (Spec E, recon-intel map).

        Fuses profile + endpoints + coverage + findings + freshness into a single
        token-lean map: CONTEXT (tech/auth/scope/posture), top findings, deterministic
        next-action hints, and copy-paste follow-up queries. Read-only. Call this at
        session start (or when picking up a domain) instead of four separate loads.

        Returns `exists: False` + a recon directive when the target is new.

        Args:
            domain: target domain.
            max_items: cap on top_findings returned (default 8).

        Returns: compact orientation dict.
        """
        return build_brief(domain, max_items=max_items)
