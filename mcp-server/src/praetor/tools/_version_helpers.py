"""version parse/compare/distance + ecosystem applicability (helpers for version_delta)."""

from __future__ import annotations

import re


_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+.]?([0-9A-Za-z.\-]+))?")


def parse_version(raw: str) -> tuple[tuple[int, int, int], str] | None:
    """('1.2.3-rc1') -> ((1, 2, 3), 'rc1'). None when unparseable."""
    if not raw:
        return None
    m = _VER_RE.search(str(raw).strip().lstrip("vV="))
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch), (m.group(4) or "")


def compare_versions(a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b. Pre-release suffixes ignored."""
    pa, pb = parse_version(a), parse_version(b)
    if not pa or not pb:
        return 0
    return (pa[0] > pb[0]) - (pa[0] < pb[0])


def version_distance(a: str, b: str) -> str:
    """'same' | 'patch' | 'minor' | 'major' | 'unknown'."""
    pa, pb = parse_version(a), parse_version(b)
    if not pa or not pb:
        return "unknown"
    (amaj, amin, apat), (bmaj, bmin, bpat) = pa[0], pb[0]
    if amaj != bmaj:
        return "major"
    if amin != bmin:
        return "minor"
    if apat != bpat:
        return "patch"
    return "same"


# ── Adaptation axes ─────────────────────────────────────────────────────────
# What actually breaks a PoC when it crosses a version boundary, per ecosystem.
# Ordered most-likely-cause first. These are shape concerns, never the vuln
# itself — the vuln is assumed present; only the delivery envelope moved.

_GENERIC_AXES = [
    "Route/path shape — the vulnerable handler may have moved or gained a prefix. Re-discover the live path before assuming the PoC's path.",
    "Request envelope — content-type and body serialization change far more often than handler logic (JSON <-> form <-> multipart <-> text/plain).",
    "Header names — framework-internal headers get renamed/prefixed across minors; a missing header usually yields a clean 400, which reads like 'not vulnerable'.",
    "Parameter naming and nesting depth — a flat param in A may be nested under an object in B.",
    "Encoding layer — added normalization in B may require double-encoding, or may have removed the decode the PoC relied on.",
    "Error surface — B may return a generic 500 where A leaked the oracle. Switch to a timing or OOB oracle before concluding failure.",
]

_ECOSYSTEM_AXES: dict[str, list[str]] = {
    "nextjs": [
        "Server Action ID derivation changed between Next minors — a hardcoded Next-Action id from the PoC will 404. Harvest the live id from the page bundle (smart_js_analyze) instead.",
        "RSC payload chunk syntax differs by React major — try the bare children chunk, the multipart action, and the text/x-component shapes.",
        "Middleware matcher semantics changed across 13/14/15 — a bypass keyed to one matcher form silently no-ops on another.",
        "x-middleware-subrequest / x-now-route-matches header names are version-specific.",
    ],
    "react": [
        "RSC wire format is React-major-specific; the chunk prefix and reference encoding both moved.",
        "Server Action ids are build-specific — never reuse an id from a published PoC.",
    ],
    "express": [
        "Body-parser defaults changed (extended qs vs simple) — nested-object payloads parse differently.",
        "Route param handling and the merge helper in use decide whether prototype-pollution keys land.",
    ],
    "spring": [
        "SpEL/OGNL evaluation contexts were progressively restricted — a working expression in A may need a different bean-resolution path in B.",
        "Actuator endpoint paths moved under /actuator in Boot 2.x.",
    ],
    "graphql": [
        "Introspection and federation helpers (_service, _entities) get gated at different versions — probe availability before building on them.",
        "Batching and alias limits change per server minor.",
    ],
    "apollo": [
        "Federation directive inheritance semantics changed at 2.9/2.10/2.11/2.12 — the exact subgraph shape matters.",
    ],
    "struts": [
        "OGNL sandbox tightened per S2 advisory; the injection location (query vs Referer vs path) matters more than the expression.",
    ],
    "sveltekit": [
        "devalue serialization and +server.ts route conventions changed across majors.",
    ],
    "nuxt": [
        "Island payload route (/__nuxt_island/) naming and hashing is version-specific.",
    ],
    "wordpress": [
        "REST namespace versioning (wp/v2) and nonce requirements differ per core minor.",
    ],
}

# Component -> variant-generator class already modelled in _cve_variant_gen.
_ECOSYSTEM_TO_CLASS = {
    "nextjs": "nextjs_cache_poisoning",
    "react": "react_server_components",
    "trpc": "trpc_sspp",
    "express": "prototype_pollution",
    "axios": "prototype_pollution",
}


def detect_ecosystem(component: str, tech_stack: str = "") -> str:
    """Best-effort ecosystem key from free-form component / tech text."""
    blob = f"{component} {tech_stack}".lower()
    for key in (
        "nextjs", "next.js", "react", "express", "spring", "apollo",
        "graphql", "struts", "sveltekit", "nuxt", "wordpress", "trpc", "axios",
    ):
        if key.replace(".", "") in blob.replace(".", "").replace(" ", ""):
            return "nextjs" if key in ("nextjs", "next.js") else key
    return ""


def assess_applicability(
    poc_version: str, target_version: str, fixed_version: str
) -> tuple[str, str]:
    """(verdict, rationale). Verdict is one of
    APPLIES_AS_IS / ADAPT_REQUIRED / LIKELY_PATCHED / UNKNOWN."""
    if fixed_version and target_version:
        cmp_fix = compare_versions(target_version, fixed_version)
        if cmp_fix >= 0:
            return (
                "LIKELY_PATCHED",
                f"target {target_version} is at or above the fixed version "
                f"{fixed_version}. Firing the PoC here burns requests and adds a "
                f"failed-probe record that hides the real gap. Confirm the fix is "
                f"actually deployed (vendored builds and backports lie both ways) "
                f"before spending further budget.",
            )

    if not poc_version or not target_version:
        return (
            "UNKNOWN",
            "poc_version or target_version missing. Fingerprint the running "
            "version first (detect_tech_stack / a build-id in the bundle / a "
            "server header) — a PoC fired without knowing the target version "
            "produces an uninterpretable result either way.",
        )

    dist = version_distance(poc_version, target_version)
    if dist == "same":
        return ("APPLIES_AS_IS", f"target and PoC are both {target_version}.")
    if dist == "patch":
        return (
            "APPLIES_AS_IS",
            f"patch-level difference ({poc_version} -> {target_version}). "
            f"Request shape is stable across patches; fire as-is, and only adapt "
            f"if the response is a clean 4xx rather than an error or a hang.",
        )
    if dist == "minor":
        return (
            "ADAPT_REQUIRED",
            f"minor-version difference ({poc_version} -> {target_version}). "
            f"The vulnerability is likely still reachable but the delivery "
            f"envelope moves at minors — this is the case where a verbatim PoC "
            f"fails and gets mis-recorded as 'not vulnerable'.",
        )
    if dist == "major":
        return (
            "ADAPT_REQUIRED",
            f"major-version difference ({poc_version} -> {target_version}). "
            f"Assume the request shape is different. Rebuild the PoC from the "
            f"vulnerability's mechanism, not from its published bytes.",
        )
    return ("UNKNOWN", "versions could not be parsed for comparison.")
