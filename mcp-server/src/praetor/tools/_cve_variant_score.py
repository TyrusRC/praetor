"""Response scoring for CVE variant probes — extracted from cve_variant_probe.py (split 2026-07-23)."""

from __future__ import annotations

import re

# ----- Scoring ---------------------------------------------------------------

_RSC_MARKERS = (
    re.compile(r"text/x-component", re.I),
    re.compile(r"\$\d+@"),
    re.compile(r"\bcreateServerReference\b"),
    re.compile(r"\bdecodeChunk\b"),
    re.compile(r"\bReact\b.*Flight", re.I | re.S),
)
_NEXT_CACHE_MARKERS = (
    re.compile(r"x-vercel-cache:\s*HIT", re.I),
    re.compile(r"x-nextjs-prerender", re.I),
    re.compile(r"x-vercel-id:.*::", re.I),
)
_SSPP_MARKERS = (
    re.compile(r"TypeError"),
    re.compile(r"Cannot (read|set|convert).*prototype", re.I),
    re.compile(r"constructor.prototype"),
)
_WS_SSRF_MARKERS = (
    re.compile(r"iam/security-credentials", re.I),
    re.compile(r"\bAccessKeyId\b"),
    re.compile(r"\bSecretAccessKey\b"),
    re.compile(r"\bx-google-metadata-request\b", re.I),
    re.compile(r"computeMetadata/v1", re.I),
    re.compile(r"\bmetadata\.google\.internal\b", re.I),
    re.compile(r"\bcompute\.metadata\.azure\.com\b", re.I),
    re.compile(r'"InstanceProfile"', re.I),
)
_NEXTJS_MW_MARKERS = (
    re.compile(r"text/x-component", re.I),
    re.compile(r"Next-Router-State-Tree", re.I),
    re.compile(r"__next_f\b"),
    re.compile(r"self\.__next_f"),
)


def _score_response(klass: str, canary: str, status: int, headers_blob: str,
                    body: str) -> tuple[str, float, str]:
    """Return (verdict, confidence, reason) for one variant response.

    CONFIRMED requires either canary echo or a class-specific marker hit AND
    a status that's plausibly a parse/code path (200/500/302).
    """
    body_short = (body or "")[:30000]
    hb = (headers_blob or "")[:8000]

    # Canary echo — strongest signal (PoC payload reached an unsanitised sink)
    if canary and canary in body_short:
        return ("CONFIRMED", 0.92,
                f"canary {canary!r} echoed in response body")
    if canary and canary in hb:
        return ("CONFIRMED", 0.88,
                f"canary {canary!r} echoed in response headers")

    markers: tuple[re.Pattern[str], ...] = ()
    if klass == "react_server_components":
        markers = _RSC_MARKERS
    elif klass == "nextjs_cache_poisoning":
        markers = _NEXT_CACHE_MARKERS
    elif klass in ("trpc_sspp", "prototype_pollution"):
        markers = _SSPP_MARKERS
    elif klass == "nextjs_ws_upgrade_ssrf":
        markers = _WS_SSRF_MARKERS
    elif klass == "nextjs_middleware_bypass":
        markers = _NEXTJS_MW_MARKERS

    hits = []
    for pat in markers:
        if pat.search(body_short) or pat.search(hb):
            hits.append(pat.pattern)

    if hits and status in (200, 500, 302):
        return ("SUSPECTED", 0.60,
                f"class-marker(s) hit: {hits[:3]}; status={status}")
    if hits:
        return ("SUSPECTED", 0.45,
                f"class-marker(s) hit but unexpected status={status}: {hits[:2]}")
    return ("FAILED", 0.10, f"no canary, no marker; status={status}")


