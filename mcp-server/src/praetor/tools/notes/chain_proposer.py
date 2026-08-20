"""propose_chains — walk findings.json, propose impact-uplift chains (W7, T3).

Senior-engineer move: standalone lows go nowhere; chained lows become criticals.
This tool reads `.burp-intel/<domain>/findings.json`, enumerates 2- and 3-step
chains over confirmed / suspected findings, and scores each chain by impact
uplift using rules distilled from `chain-findings.md` and the 2024-2026 H1
top-payout reports.

Only `confirmed` and `suspected` findings participate. `stale` /
`likely_false_positive` are excluded by design — Rule 16 + dedup contract.

Output shape per chain:
    {
      "anchors": [finding_id, ...],          # ordered by exploit progression
      "vuln_types": [vt, ...],
      "score": 0..100,                       # impact uplift, higher = stronger chain
      "severity": "critical|high|medium",    # post-chain severity
      "rationale": "open_redirect -> token_theft -> ATO ...",
      "evidence_summary": "..."
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..intel._internals import _intel_path


_PROGRESSIONS: list[dict[str, Any]] = [
    {
        "name": "open_redirect_to_ato",
        "match": [["open_redirect"], ["oauth", "csrf", "token_leak"], ["ato"]],
        "min_len": 2,
        "score": 85,
        "severity": "critical",
        "rationale": "open redirect lands attacker on a controlled origin → exfil session/access token via Referer/postMessage/OAuth code → full account takeover",
    },
    {
        "name": "csrf_email_change_ato",
        "match": [["csrf"], ["mass_assignment", "auth_bypass", "account_email"], ["ato"]],
        "min_len": 2,
        "score": 90,
        "severity": "critical",
        "rationale": "CSRF on email-change → attacker pivots password reset to controlled inbox → full ATO",
    },
    {
        "name": "info_disclosure_to_idor",
        "match": [["info_disclosure", "stack_trace", "verbose_error", "debug"], ["idor", "bola"]],
        "min_len": 2,
        "score": 70,
        "severity": "high",
        "rationale": "leaked internal IDs / model names enumerate IDOR victims",
    },
    {
        "name": "ssrf_to_cloud_credentials",
        "match": [["ssrf"], ["cloud_metadata", "cloud_imds", "iam"], ["rce", "cred_theft"]],
        "min_len": 2,
        "score": 95,
        "severity": "critical",
        "rationale": "SSRF reaches 169.254.169.254 → exfil IAM creds → cross-service pivot",
    },
    {
        "name": "xss_csrf_admin_action",
        "match": [["xss", "dom_xss"], ["csrf"], ["admin_action", "privilege_escalation"]],
        "min_len": 2,
        "score": 88,
        "severity": "critical",
        "rationale": "XSS bypasses SameSite + CSRF token gating → forced admin action under victim session",
    },
    {
        "name": "subdomain_takeover_cookie_ato",
        "match": [["subdomain_takeover"], ["cookie_scope", "session_fixation"], ["ato"]],
        "min_len": 2,
        "score": 92,
        "severity": "critical",
        "rationale": "takeover of *.target.com subdomain inherits parent-scoped cookies → session hijack",
    },
    {
        "name": "proto_pollution_to_dom_xss",
        "match": [["prototype_pollution"], ["dom_xss", "xss"]],
        "min_len": 2,
        "score": 80,
        "severity": "high",
        "rationale": "client-side prototype pollution pollutes a DOM sink → executable XSS",
    },
    {
        "name": "cspp_to_sspp",
        "match": [["cspp", "prototype_pollution"], ["sspp", "rce"]],
        "min_len": 2,
        "score": 90,
        "severity": "critical",
        "rationale": "client-side prototype pollution gadget reaches a server reflector → SSPP → RCE on Express/Fastify",
    },
    {
        "name": "cache_deception_to_pii_mass",
        "match": [["web_cache_deception", "cache_poisoning"], ["idor", "info_disclosure"]],
        "min_len": 2,
        "score": 78,
        "severity": "high",
        "rationale": "cache deception stores per-user response under public key → mass PII leak",
    },
    {
        "name": "idor_plus_auth_bypass_enumeration",
        "match": [["auth_bypass", "broken_access"], ["idor", "bola", "id_enumeration"]],
        "min_len": 2,
        "score": 82,
        "severity": "high",
        "rationale": "auth-bypass on collection endpoint × predictable IDs = wholesale data theft",
    },
    {
        "name": "host_header_to_cache_poisoning",
        "match": [["host_header"], ["cache_poisoning"], ["xss", "open_redirect"]],
        "min_len": 2,
        "score": 80,
        "severity": "high",
        "rationale": "Host-header injection poisons shared cache → mass victim impact",
    },
    {
        "name": "csrf_logout_no_chain",
        # Suppression rule: CSRF on logout alone is NEVER_SUBMIT; explicitly do not propose.
        "match": [["csrf_logout"]],
        "min_len": 99,
        "score": 0,
        "severity": "low",
        "rationale": "(suppressed — never_submit alone)",
    },
    {
        "name": "jwt_alg_none_to_ato",
        "match": [["jwt"], ["auth_bypass"], ["ato"]],
        "min_len": 2,
        "score": 90,
        "severity": "critical",
        "rationale": "JWT alg=none / key confusion → forge admin token → ATO",
    },
    {
        "name": "graphql_introspection_to_field_idor",
        "match": [["graphql"], ["idor", "bola", "mass_assignment"]],
        "min_len": 2,
        "score": 72,
        "severity": "high",
        "rationale": "GraphQL introspection reveals sensitive types → BOLA on field resolvers",
    },
    {
        "name": "smuggling_to_internal_route",
        "match": [["request_smuggling", "http_desync"], ["auth_bypass", "ssrf", "info_disclosure"]],
        "min_len": 2,
        "score": 95,
        "severity": "critical",
        "rationale": "HTTP smuggling bypasses front-end ACL → reach internal route",
    },
    {
        "name": "parser_differential_auth_bypass",
        "match": [["parser_differential"], ["auth_bypass", "privilege_escalation"]],
        "min_len": 2,
        "score": 88,
        "severity": "critical",
        "rationale": "URL/header/JSON parser disagreement between front-end and back-end → ACL bypass",
    },
]


def _vt(f: dict[str, Any]) -> str:
    return str(f.get("vuln_type") or f.get("category") or "").lower()


def _matches_step(finding_vt: str, step_alts: list[str]) -> bool:
    for alt in step_alts:
        if alt in finding_vt:
            return True
    return False


def _find_chain(progression: dict[str, Any], pool: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Greedy: for each step, pick the highest-confidence matching finding not already used."""
    steps = progression["match"]
    if progression.get("min_len", 99) > len(pool):
        return []
    chains: list[list[dict[str, Any]]] = []
    used_ids_global: set[str] = set()

    for first in pool:
        if not _matches_step(_vt(first), steps[0]):
            continue
        chain = [first]
        used = {first.get("id") or first.get("finding_id") or str(id(first))}
        for step_alts in steps[1:]:
            best = None
            for f in pool:
                fid = f.get("id") or f.get("finding_id") or str(id(f))
                if fid in used:
                    continue
                if _matches_step(_vt(f), step_alts):
                    if best is None or float(f.get("confidence", 0)) > float(best.get("confidence", 0)):
                        best = f
            if best is None:
                break
            chain.append(best)
            used.add(best.get("id") or best.get("finding_id") or str(id(best)))
        if len(chain) >= progression.get("min_len", 2):
            sig = tuple(sorted(c.get("id") or c.get("finding_id") or str(id(c)) for c in chain))
            sig_str = "|".join(sig)
            if sig_str not in used_ids_global:
                used_ids_global.add(sig_str)
                chains.append(chain)
    return chains


def register(mcp: FastMCP):

    @mcp.tool()
    async def propose_chains(
        domain: str,
        min_score: int = 60,
        max_chains: int = 20,
        include_suspected: bool = True,
    ) -> dict:
        """Walk findings.json and propose impact-uplift chains, scored by exploit progression.

        Reads `.burp-intel/<domain>/findings.json`. Excludes `stale` and
        `likely_false_positive`. Each chain is matched against a rulebook of
        known progressions (open_redirect→ATO, SSRF→IAM, JWT→ATO, parser-diff
        →auth bypass, etc.) and scored by impact uplift.

        Args:
            domain: target domain
            min_score: minimum chain score to include (default 60)
            max_chains: cap on returned chains
            include_suspected: include suspected findings (default True)
        """
        path: Path = _intel_path(domain) / "findings.json"
        if not path.exists():
            return {
                "domain": domain,
                "chains": [],
                "total_findings_considered": 0,
                "note": "no findings.json — run testing + save_finding first",
            }

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": f"failed to read findings.json: {exc}"}

        items = data if isinstance(data, list) else data.get("findings", [])
        valid_states = {"confirmed"} | ({"suspected"} if include_suspected else set())
        pool = [
            f for f in items
            if str(f.get("status", "confirmed")).lower() in valid_states
        ]

        proposed: list[dict[str, Any]] = []
        for progression in _PROGRESSIONS:
            if progression["score"] < min_score:
                continue
            for chain in _find_chain(progression, pool):
                anchors = [c.get("id") or c.get("finding_id") for c in chain]
                vts = [_vt(c) for c in chain]
                ev = " → ".join(
                    f"{c.get('endpoint', '?')}[{_vt(c)}]" for c in chain
                )
                proposed.append({
                    "progression": progression["name"],
                    "anchors": anchors,
                    "vuln_types": vts,
                    "score": progression["score"],
                    "severity": progression["severity"],
                    "rationale": progression["rationale"],
                    "evidence_summary": ev,
                })

        proposed.sort(key=lambda c: c["score"], reverse=True)
        return {
            "domain": domain,
            "total_findings_considered": len(pool),
            "chains": proposed[:max_chains],
            "rule_count": len([p for p in _PROGRESSIONS if p["score"] >= min_score]),
        }
