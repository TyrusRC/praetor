"""plan_attack_paths — beam-search kill-chain planner over confirmed findings.

Where `propose_chains` matches findings against a fixed rulebook of known
progressions, this searches the capability graph: it seeds the attacker's held
capabilities from the real findings, beam-searches escalation transitions to the
high-value objectives (RCE / cloud-cred theft / ATO / mass-PII / forced admin
action), and — the part the rulebook cannot do — reports NEAR-MISS objectives:
paths blocked by exactly one missing capability, naming the vuln class that would
grant it. That missing capability is the operator's next proof to obtain
(Rule 29: every LOW gets one escalation cycle).

Search-based, evidence-weighted, and additive to `propose_chains`; neither
replaces the other.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor.tools.intel._internals import _intel_path

from ._attack_path_data import (
    _CAP_HUMAN, _CLASS_GRANTS, _OBJECTIVES, _TRANSITIONS,
)

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}
_STATUS_CONFIDENCE = {"confirmed": 0.9, "suspected": 0.6}


def _vt(f: dict[str, Any]) -> str:
    return str(f.get("vuln_type") or f.get("category") or "").lower()


def _fid(f: dict[str, Any]) -> str:
    return str(f.get("id") or f.get("finding_id") or f.get("title") or "?")


def _evidence_weight(f: dict[str, Any]) -> float:
    """0..1 evidence weight from severity and confidence (or status default)."""
    sev = str(f.get("severity", "medium")).lower()
    sw = _SEVERITY_WEIGHT.get(sev, 0.6)
    conf = f.get("confidence")
    if conf is None:
        conf = _STATUS_CONFIDENCE.get(str(f.get("status", "confirmed")).lower(), 0.6)
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        conf = 0.6
    return sw * max(0.1, min(conf, 1.0))


def _seed_capabilities(pool: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """capability token -> best granting finding {fid, vuln_type, weight}."""
    seeds: dict[str, dict[str, Any]] = {}
    for f in pool:
        vt = _vt(f)
        w = _evidence_weight(f)
        for token, caps in _CLASS_GRANTS.items():
            if token in vt:
                for cap in caps:
                    prev = seeds.get(cap)
                    if prev is None or w > prev["weight"]:
                        seeds[cap] = {"fid": _fid(f), "vuln_type": vt, "weight": w}
    return seeds


def _closure(held: set[str]) -> set[str]:
    """All capabilities reachable from `held` via transitions (fixpoint)."""
    caps = set(held)
    changed = True
    while changed:
        changed = False
        for need, gives, _u, _t, _d in _TRANSITIONS:
            if gives not in caps and need <= caps:
                caps.add(gives)
                changed = True
    return caps


def _beam_chains(
    seeds: dict[str, dict[str, Any]], beam_width: int, max_depth: int,
) -> list[dict[str, Any]]:
    """Beam-search transition paths from seed caps to objectives.

    Each state carries the ordered path of transitions applied; the score is the
    objective base value scaled by the mean seed-evidence weight and the product
    of the transition uplifts along the path. Best path per objective wins.
    """
    seed_caps = frozenset(seeds)
    mean_seed_w = (
        sum(s["weight"] for s in seeds.values()) / len(seeds) if seeds else 0.0
    )
    start = {"caps": seed_caps, "path": [], "mult": 1.0}
    frontier = [start]
    best_by_obj: dict[str, dict[str, Any]] = {}

    for _ in range(max_depth):
        nxt: list[dict[str, Any]] = []
        for st in frontier:
            for need, gives, uplift, tech, desc in _TRANSITIONS:
                if gives in st["caps"] or not need <= st["caps"]:
                    continue
                ns = {
                    "caps": st["caps"] | {gives},
                    "path": st["path"] + [{
                        "capability": gives, "uplift": uplift,
                        "attack_ck": tech, "action": desc,
                        # seed caps consumed by this step (attribution).
                        "from": sorted(need & seed_caps),
                    }],
                    "mult": st["mult"] * uplift,
                }
                nxt.append(ns)
                if gives in _OBJECTIVES:
                    sev, base, name = _OBJECTIVES[gives]
                    score = round(base * mean_seed_w * ns["mult"])
                    prev = best_by_obj.get(gives)
                    if prev is None or score > prev["score"]:
                        best_by_obj[gives] = {
                            "objective": name, "objective_cap": gives,
                            "severity": sev, "score": score,
                            "steps": ns["path"],
                        }
        if not nxt:
            break
        # Rank the frontier by current chain strength and keep the beam.
        nxt.sort(key=lambda s: s["mult"], reverse=True)
        frontier = nxt[:beam_width]

    # Attach the seed findings each chain actually rests on.
    for chain in best_by_obj.values():
        used_caps = {c for step in chain["steps"] for c in step["from"]}
        chain["seed_findings"] = sorted(
            {f"{seeds[c]['fid']} ({seeds[c]['vuln_type']})" for c in used_caps if c in seeds}
        )
    return sorted(best_by_obj.values(), key=lambda c: c["score"], reverse=True)


def _near_misses(reachable: set[str], seeds: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Objectives blocked by exactly one missing capability -> next proof to get."""
    # Reverse map: capability -> vuln classes that grant it (for the operator hint).
    grantors: dict[str, list[str]] = {}
    for token, caps in _CLASS_GRANTS.items():
        for cap in caps:
            grantors.setdefault(cap, []).append(token)

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for need, gives, _u, _t, desc in _TRANSITIONS:
        if gives not in _OBJECTIVES or gives in reachable:
            continue
        missing = need - reachable
        if len(missing) != 1:
            continue
        gap = next(iter(missing))
        # Actionable only if a *finding* can grant the gap. An intermediate
        # capability (produced only by another transition) is a deeper miss, not
        # a single next proof — skip it rather than emit "go get <intermediate>".
        if not grantors.get(gap):
            continue
        _sev, _base, name = _OBJECTIVES[gives]
        key = f"{gives}:{gap}"
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "objective": name,
            "missing_capability": _CAP_HUMAN.get(gap, gap),
            "next_proof_needed": grantors.get(gap, [gap]),
            "would_complete": desc,
            "have": sorted(c for c in need if c in reachable) or ["(recon only)"],
        })
    return out


async def plan_attack_paths_impl(
    domain: str,
    beam_width: int = 6,
    max_depth: int = 5,
    include_suspected: bool = True,
) -> dict:
    path: Path = _intel_path(domain) / "findings.json"
    if not path.exists():
        return {
            "domain": domain, "kill_chains": [], "near_misses": [],
            "note": "no findings.json — save_finding first, then re-plan",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"failed to read findings.json: {exc}"}

    items = data if isinstance(data, list) else data.get("findings", [])
    valid = {"confirmed"} | ({"suspected"} if include_suspected else set())
    pool = [f for f in items if str(f.get("status", "confirmed")).lower() in valid]

    seeds = _seed_capabilities(pool)
    if not seeds:
        return {
            "domain": domain, "considered": len(pool),
            "kill_chains": [], "near_misses": [],
            "note": "no findings map to an attacker capability yet — hunt for an "
                    "authorization / injection / auth primitive first (Rule 29)",
        }

    reachable = _closure(set(seeds))
    chains = _beam_chains(seeds, beam_width, max_depth)
    near = _near_misses(reachable, seeds)

    return {
        "domain": domain,
        "considered": len(pool),
        "capabilities_held": sorted(_CAP_HUMAN.get(c, c) for c in seeds),
        "kill_chains": chains,
        "near_misses": near,
        "note": (
            "Search-based (beam) over the capability graph — complements "
            "propose_chains (rulebook). near_misses name the single capability "
            "blocking each unreachable objective; that is your next proof."
        ),
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def plan_attack_paths(
        domain: str,
        beam_width: int = 6,
        max_depth: int = 5,
        include_suspected: bool = True,
    ) -> dict:
        """Beam-search kill-chains from confirmed findings to high-value objectives.

        Seeds attacker capabilities from `.burp-intel/<domain>/findings.json`
        (confirmed + suspected), then searches escalation transitions to the
        objectives RCE / cloud-cred theft / ATO / forced-admin-action / mass-PII.
        Returns ranked kill_chains (ordered steps, ATT&CK ids, seed findings,
        evidence-weighted score) AND near_misses — objectives blocked by exactly
        one missing capability, naming the vuln class that would grant it (your
        next proof, Rule 29). Complements propose_chains; does not replace it.

        Args:
            domain: target domain (findings.json lookup).
            beam_width: frontier kept per depth (default 6).
            max_depth: max escalation hops (default 5).
            include_suspected: seed from suspected findings too (default True).
        """
        return await plan_attack_paths_impl(domain, beam_width, max_depth, include_suspected)
