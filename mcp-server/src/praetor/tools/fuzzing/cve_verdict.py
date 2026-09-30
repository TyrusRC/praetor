"""`assess_cve_exploitability` — one-call "is this CVE exploitable on THIS target".

Phase 1, component 3 of the fuzzing/CVE lane (docs/superpowers/specs/
2026-09-30-fuzzing-cve-lane-design.md). Orchestrates the EXISTING chain — no
new CVE intelligence is invented here:

    candidate CVEs (cve / tech+version / profile.json fingerprint)
      -> KEV + EPSS weight        (pure core `_shodan_cve_lookup`, behind kev_epss_enrich)
      -> LIVE precondition check   (route reachable through Burp -> proxy_history_index)
      -> adapted BENIGN PoC        (assess_applicability delta + the probe_cve_with_variants
                                    generator/scorer cores, benign canary only)
      -> per-CVE verdict {reachable, precondition_met, exploitable_here, evidence}

`exploitable_here` is TRUE only when the benign PoC actually FIRED and produced
class-consistent evidence with a citable proxy_history_index. A version/banner
match alone is `reachable`, never `exploitable_here` (Rule 13b/13c: a scanner or
banner guess is a lead, not proof). No auto-save — the operator runs save_finding.

Safety (HARD Rules 5-9): benign markers only (canary echo / class marker /
timing / OOB). Never destructive, never exfil. Memory-corruption / parser CVEs
cannot be proven benignly over a web probe -> handed to the Phase-2 CVE->AFL
bridge (afl_fuzz_target / fuzz_upload), not force-fired here.
"""

from __future__ import annotations

import json
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client
# KEV/EPSS pure core (the function kev_epss_enrich itself wraps) + candidate lookup.
from praetor.tools.cve.shodan import _shodan_cve_lookup, _shodan_cves_query
# PoC-adaptation pure core (behind adapt_poc_to_version) — version-delta verdict.
from praetor.tools._version_helpers import assess_applicability
# Variant generators + scorer (the same cores probe_cve_with_variants fires) —
# reused so the benign PoC uses identical payload shapes, not a reimplementation.
from praetor.tools._cve_variant_gen import _resolve_class, _GENERATORS
from praetor.tools._cve_variant_score import _score_response
from praetor.tools.intel._internals import _intel_path


# --- memory-corruption / parser classification (Phase-2 CVE->AFL bridge gate) --

# Spec names CWE-119/125/416/787 as the memory-corruption/parser handoff set.
_MEMCORR_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
    "CWE-190", "CWE-416", "CWE-787", "CWE-824",
}
_MEMCORR_KEYWORDS = (
    "out-of-bounds", "out of bounds", "oob read", "oob write",
    "heap overflow", "heap-based buffer overflow", "buffer overflow",
    "stack overflow", "stack-based buffer overflow",
    "use-after-free", "use after free", "double free", "double-free",
    "memory corruption", "integer overflow", "type confusion",
)
_CWE_HINTS = (
    ("use-after-free", "CWE-416"), ("use after free", "CWE-416"),
    ("double free", "CWE-416"), ("double-free", "CWE-416"),
    ("out-of-bounds write", "CWE-787"), ("oob write", "CWE-787"),
    ("heap overflow", "CWE-787"), ("heap-based buffer overflow", "CWE-787"),
    ("buffer overflow", "CWE-787"), ("stack overflow", "CWE-121"),
    ("out-of-bounds read", "CWE-125"), ("oob read", "CWE-125"),
    ("out-of-bounds", "CWE-125"), ("out of bounds", "CWE-125"),
    ("integer overflow", "CWE-190"), ("memory corruption", "CWE-119"),
)


def _infer_cwe(summary: str) -> str:
    """Best-effort CWE from the CVE summary (Shodan CVEDB carries no CWE field)."""
    s = (summary or "").lower()
    for kw, cwe in _CWE_HINTS:
        if kw in s:
            return cwe
    return ""


def _is_memory_corruption(cwe: str, summary: str) -> bool:
    """True when the candidate is a memory-corruption / file-format-parser class.

    These cannot be proven benignly over a web probe (the deliverable is a
    crash / sanitizer report, not a web marker) -> Phase-2 CVE->AFL bridge.
    """
    if cwe and cwe.upper() in _MEMCORR_CWES:
        return True
    s = (summary or "").lower()
    return any(kw in s for kw in _MEMCORR_KEYWORDS)


# --- small pure helpers ------------------------------------------------------

def _split_tech_version(item: str) -> tuple[str, str]:
    """Parse a tech_stack entry ('nginx/1.18.0', 'PHP:7.4', 'Apache 2.4.49')."""
    raw = (item or "").strip()
    for sep in ("/", ":"):
        if sep in raw:
            t, _, v = raw.partition(sep)
            return t.strip(), v.strip()
    parts = raw.split()
    if len(parts) == 2 and any(c.isdigit() for c in parts[1]):
        return parts[0].strip(), parts[1].strip()
    return raw, ""


def _proxy_idx(resp: dict) -> int:
    """Citable Burp index from a curl/session response, or -1."""
    for key in ("proxy_history_index", "proxy_index", "index"):
        v = resp.get(key)
        if isinstance(v, int) and v >= 0:
            return v
    return -1


def _target_url(domain: str, endpoint: str) -> str:
    if endpoint:
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        base = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
        return base.rstrip("/") + "/" + endpoint.lstrip("/")
    return domain if domain.startswith(("http://", "https://")) else f"https://{domain}"


def _assemble_cve_verdict(
    *,
    cve: str,
    cwe: str,
    kev: bool,
    epss: float | None,
    reachable: bool,
    precondition_met: bool,
    poc_verdict: str,
    evidence: dict[str, Any],
    poc_summary: str,
    memcorr: bool,
) -> dict[str, Any]:
    """Pure verdict assembly — the exploitable_here gate. No I/O; unit-tested.

    exploitable_here is TRUE only when the benign PoC FIRED (`CONFIRMED`) AND
    carries citable evidence (proxy_history_index or collaborator id). Everything
    else — a reachable route, a version match, a SUSPECTED partial — is a lead,
    not proof (Rule 13b/13c).
    """
    phi = evidence.get("proxy_history_index", -1)
    cid = evidence.get("collaborator_interaction_id")
    has_evidence = (isinstance(phi, int) and phi >= 0) or bool(cid)
    exploitable_here = poc_verdict == "CONFIRMED" and has_evidence

    if memcorr:
        # Memory-corruption / parser CVE: a benign web PoC cannot prove it.
        exploitable_here = False
        confidence = "medium" if precondition_met else "low"
        nxt = (
            "memory-corruption/parser CWE -> Phase-2 CVE->AFL bridge: seed the "
            "fuzz lane (afl_fuzz_target with a local build, else fuzz_upload) "
            "with the CVE PoC corpus + format dictionary to reproduce the crash. "
            "Not provable over a benign web probe."
        )
    elif exploitable_here:
        confidence = "high"
        nxt = (
            "benign PoC fired with class-consistent evidence -> assess_finding "
            "then save_finding (operator-owned; no auto-save)."
        )
    elif poc_verdict == "SUSPECTED":
        confidence = "medium"
        nxt = (
            "partial signal only -> raise max_variants / supply baseline_payload / "
            "harvest action_id and re-run probe_cve_with_variants. NOT "
            "exploitable_here yet (Rule 13b)."
        )
    elif not reachable:
        confidence = "none"
        nxt = (
            "route unreachable through Burp -> confirm endpoint + scope "
            "(blocker, Rule 32a: ask; do not mark N/A)."
        )
    elif not precondition_met:
        confidence = "low"
        nxt = (
            "host responded but the affected route/feature was not confirmed "
            "present -> verify the vulnerable version/config, then re-probe."
        )
    else:  # reachable + precondition, but the PoC did not fire
        confidence = "low"
        nxt = (
            "preconditions met but the benign PoC did not fire -> a version/banner "
            "match is a lead, not proof (Rule 13c): refine the payload/variant or "
            "supply baseline_payload. NOT exploitable_here."
        )

    out_evidence: dict[str, Any] = {}
    if isinstance(phi, int) and phi >= 0:
        out_evidence["proxy_history_index"] = phi
    if cid:
        out_evidence["collaborator_interaction_id"] = cid

    return {
        "cve": cve,
        "cwe": cwe or None,
        "kev": bool(kev),
        "epss": epss,
        "reachable": bool(reachable),
        "precondition_met": bool(precondition_met),
        "exploitable_here": bool(exploitable_here),
        "confidence": confidence,
        "evidence": out_evidence,
        "poc_summary": poc_summary,
        "next": nxt,
    }


# --- benign PoC firing (reuses the probe_cve_with_variants cores) ------------

def _canary() -> str:
    import secrets
    return "PRAETOR-" + secrets.token_hex(4).upper()


async def _fire_benign_poc(
    cve: str,
    target_url: str,
    *,
    baseline_payload: str = "",
    action_id: str = "",
    max_variants: int = 6,
    per_req_timeout: int = 12,
) -> tuple[str, int, str]:
    """Fire the adapted BENIGN PoC and return (verdict, proxy_history_index, reason).

    Reuses the exact variant generators + scorer that back
    probe_cve_with_variants — identical benign payloads, short-circuit on first
    CONFIRMED. All traffic routes through Burp so a hit is citable.

    NOTE (known ceiling): compact inline loop, no Burp-session auth and capped at
    `max_variants` shapes. For a full auth-aware sweep, drive
    probe_cve_with_variants directly; this is the verdict-tool fast path.
    """
    klass = _resolve_class(cve, "")
    gen = _GENERATORS.get(klass)
    if gen is None:
        return ("NOT_FIRED", -1,
                f"no built-in variant generator for class {klass!r} ({cve}) — "
                f"supply baseline_payload or test manually")

    canary = _canary()
    variants = (gen(baseline_payload or "", canary, action_id or "") or [])[:max_variants]
    if not variants:
        return ("NOT_FIRED", -1,
                f"class {klass!r} needs a baseline_payload (no built-in variants)")

    best = ("FAILED", -1, "no variant confirmed")
    best_conf = 0.10
    for v in variants:
        url = target_url
        if v.get("url_suffix"):
            url = f"{url}{v['url_suffix']}"
        if v.get("query"):
            url = f"{url}{'&' if '?' in url else '?'}{v['query']}"
        resp = await client.post("/api/http/curl", json={
            "method": v["method"],
            "url": url,
            "headers": dict(v.get("headers") or {}),
            "data": v.get("body", ""),
            "timeout": per_req_timeout,
        })
        if not isinstance(resp, dict) or "error" in resp:
            continue
        status = int(resp.get("status_code", 0) or 0)
        body = resp.get("response_body") or ""
        rhdrs = resp.get("response_headers") or ""
        if isinstance(rhdrs, (list, dict)):
            rhdrs = json.dumps(rhdrs)
        idx = _proxy_idx(resp)
        verdict, conf, reason = _score_response(klass, canary, status, str(rhdrs), str(body))
        if verdict == "CONFIRMED":
            return ("CONFIRMED", idx, f"{v['label']}: {reason}")
        if verdict == "SUSPECTED" and conf > best_conf:
            best_conf = conf
            best = ("SUSPECTED", idx, f"{v['label']}: {reason}")
    return best


# --- registration ------------------------------------------------------------

def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def assess_cve_exploitability(
        domain: str,
        cve: str = "",
        tech: str = "",
        version: str = "",
        endpoint: str = "",
    ) -> dict:
        """Verdict: is a CVE actually exploitable on THIS target (benign, evidence-backed)?

        Orchestrates the existing CVE chain into one per-CVE verdict — candidate
        resolution (cve, or tech+version, or the target's saved fingerprint) ->
        KEV/EPSS weight -> LIVE precondition probe through Burp -> adapted BENIGN
        PoC. `exploitable_here` is TRUE only when the benign PoC fired and left
        class-consistent evidence with a proxy_history_index; a version/banner
        match alone is `reachable`, never `exploitable_here` (Rule 13b/13c).

        Benign markers only (HARD Rules 5-9); no auto-save (operator runs
        save_finding). Memory-corruption / parser CVEs are routed to the Phase-2
        CVE->AFL bridge rather than force-fired over the web.

        Args:
            domain: Target domain (used for the live probe + fingerprint fallback).
            cve: A specific CVE id to assess. If empty, candidates are derived.
            tech: Product/component (e.g. 'nginx', 'apache', 'struts2') when no
                cve is given.
            version: Running version of `tech`, for the PoC-adaptation delta.
            endpoint: Path or URL to probe for the precondition check; defaults to
                the domain root.
        """
        if not domain:
            return {"error": "domain is required (the live probe + fingerprint need it)."}

        cap = 5
        candidates: list[str] = []
        src = ""

        # 1) Candidate CVEs.
        if cve:
            candidates = [cve.strip().upper()]
            src = "explicit cve"
        elif tech:
            src = f"tech={tech}"
            res = await _shodan_cves_query(
                {"product": tech.strip().lower(), "sort_by_epss": "true"}, limit=cap)
            if isinstance(res, list):
                candidates = [c["id"] for c in res if c.get("id")]
        else:
            # Fallback: the target's saved fingerprint (Rule 20a — use prior intel).
            try:
                profile_path = _intel_path(domain) / "profile.json"
                if profile_path.exists():
                    prof = json.loads(profile_path.read_text(encoding="utf-8"))
                    for item in prof.get("tech_stack", []):
                        t, v = _split_tech_version(str(item))
                        if not t:
                            continue
                        tech = tech or t
                        version = version or v
                        res = await _shodan_cves_query(
                            {"product": t.lower(), "sort_by_epss": "true"}, limit=cap)
                        if isinstance(res, list) and res:
                            candidates = [c["id"] for c in res if c.get("id")]
                            src = f"fingerprint tech={t} version={v or '?'}"
                            break
            except Exception as e:
                return {"error": f"fingerprint load failed for {domain!r}: {e}"}

        if not candidates:
            # Rule 32a: a missing prerequisite is a blocker to ASK, not a guess.
            return {
                "error": (
                    "no candidate CVEs — supply `cve=`, or `tech=` (with `version=`), "
                    "or run map_tech_to_cves / a fingerprint pass so "
                    f".burp-intel/{domain}/profile.json carries a tech_stack. "
                    "(Rule 32a: blocker -> ask, do not guess.)"
                ),
                "domain": domain,
            }

        candidates = candidates[:cap]
        url = _target_url(domain, endpoint)

        # 2) Live precondition probe (once per target; reused for every candidate).
        pre = await client.post("/api/http/curl", json={
            "method": "GET", "url": url, "timeout": 12})
        if isinstance(pre, dict) and "error" not in pre:
            pre_status = int(pre.get("status_code", 0) or 0)
            pre_idx = _proxy_idx(pre)
            reachable = pre_status > 0
            precondition_met = reachable and pre_status not in (404, 501)
        else:
            pre_status, pre_idx = 0, -1
            reachable = False
            precondition_met = False

        # 3) Per-candidate: enrich (KEV/EPSS) -> classify -> fire benign PoC.
        assessed: list[dict] = []
        t_start = time.monotonic()
        for cid in candidates:
            look = await _shodan_cve_lookup(cid)
            if isinstance(look, dict):
                kev = bool(look.get("kev"))
                epss = look.get("epss")
                summary = look.get("summary") or ""
            else:
                kev, epss, summary = False, None, ""
            cwe = _infer_cwe(summary)
            memcorr = _is_memory_corruption(cwe, summary)

            # Version-delta note (adapt_poc_to_version pure core).
            delta_verdict, _rationale = assess_applicability(
                "", version, "") if version else ("UNKNOWN", "")

            poc_verdict, poc_idx, poc_reason = "NOT_FIRED", -1, ""
            if memcorr:
                # TODO(Phase-2 CVE->AFL bridge): when memcorr, hand off to the
                # fuzz lane instead of a web probe — seed afl_fuzz_target (local
                # build) or fuzz_upload with this CVE's PoC corpus + format
                # dictionary, reproduce the crash, triage exploitability, then
                # confirm on target. Marked here; NOT implemented in Phase 1.
                poc_reason = "memory-corruption/parser class — deferred to fuzz lane"
            elif reachable:
                poc_verdict, poc_idx, poc_reason = await _fire_benign_poc(cid, url)
            else:
                poc_reason = "route unreachable — PoC not fired"

            poc_summary = poc_reason
            if version:
                poc_summary = f"target v{version} ({delta_verdict}); {poc_reason}"

            assessed.append(_assemble_cve_verdict(
                cve=cid,
                cwe=cwe,
                kev=kev,
                epss=epss,
                reachable=reachable,
                precondition_met=precondition_met,
                poc_verdict=poc_verdict,
                evidence={"proxy_history_index": poc_idx},
                poc_summary=poc_summary,
                memcorr=memcorr,
            ))

        exploitable = sum(1 for a in assessed if a["exploitable_here"])
        memcorr_n = sum(1 for a in assessed if a["next"].startswith("memory-corruption"))
        summary = (
            f"assess_cve_exploitability[{src}] target={url} "
            f"precondition_index={pre_idx} status={pre_status}: "
            f"{len(assessed)} CVE(s) assessed, {exploitable} exploitable_here, "
            f"{memcorr_n} routed to Phase-2 fuzz lane. "
            f"({int((time.monotonic() - t_start) * 1000)}ms)"
        )

        return {
            "target": url,
            "precondition": {"proxy_history_index": pre_idx, "status": pre_status,
                             "reachable": reachable, "route_present": precondition_met},
            "assessed": assessed,
            "summary": summary,
        }
