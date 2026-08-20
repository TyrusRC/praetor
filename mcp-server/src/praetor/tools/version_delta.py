"""`adapt_poc_to_version` — turn a PoC written for version A into candidates for version B.

Operator gap: a public PoC targets version A, the target runs version B (also
in the affected range), and the PoC is fired verbatim. It fails on a shape
change that has nothing to do with the vulnerability — a renamed header, a new
serialization envelope, a moved route — and the finding is recorded as
"not vulnerable". The reflex fix is to go read another advisory; the correct
one is to reason about what changed between A and B.

This tool does the deterministic half of that reasoning so the agent does not
have to guess:

  1. Parse and compare the two versions. Say where the target sits relative to
     the PoC version and to the fix version.
  2. Decide whether the PoC transfers as-is, needs adaptation, or the target is
     very likely already patched — and say which, explicitly.
  3. Emit the adaptation axes that actually break cross-version PoCs for that
     component, ordered by how often they are the cause.
  4. Emit ready-to-fire payload candidates when the component's request shape is
     already modelled in the CVE variant generators.

Advisory lookups appear last and are framed as inputs to confirm the reasoning,
not as the deliverable. Zero deps.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP


# ── Version parsing ─────────────────────────────────────────────────────────

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


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def adapt_poc_to_version(
        component: str,
        poc_version: str = "",
        target_version: str = "",
        fixed_version: str = "",
        cve_id: str = "",
        vuln_class: str = "",
        poc_payload: str = "",
        tech_stack: str = "",
        target_url: str = "",
    ) -> str:
        """Adapt a PoC written for one version to the version actually running. Use BEFORE firing a public PoC.

        Answers the question a verbatim PoC skips: does this transfer, and if
        not, what specifically has to change? Returns an applicability verdict,
        the adaptation axes that break cross-version PoCs for this ecosystem,
        ready-to-fire follow-up calls, and — last — the sources to confirm the
        reasoning against.

        Args:
            component: Product/framework, e.g. 'next.js', 'apollo-server', 'struts2'.
            poc_version: Version the public PoC was written against.
            target_version: Version the target actually runs (fingerprint first).
            fixed_version: Version the vendor fixed it in, when known.
            cve_id: CVE or alias, for the variant-generator lookup.
            vuln_class: Explicit class override when the CVE is unmapped.
            poc_payload: The public PoC body/payload, used as the mutation seed.
            tech_stack: Extra fingerprint context ('node,express,redis').
            target_url: Target URL, used to render the follow-up calls.
        """
        if not component:
            return "Error: component is required (e.g. 'next.js', 'struts2', 'apollo-server')."

        verdict, rationale = assess_applicability(poc_version, target_version, fixed_version)
        eco = detect_ecosystem(component, tech_stack)
        dist = version_distance(poc_version, target_version) if poc_version and target_version else "unknown"

        out: list[str] = [
            f"=== PoC Version Adaptation: {component} ===",
            "",
            f"PoC version    : {poc_version or '(unknown)'}",
            f"Target version : {target_version or '(unknown — fingerprint first)'}",
            f"Fixed in       : {fixed_version or '(unknown)'}",
            f"Distance       : {dist}",
            "",
            f"VERDICT: {verdict}",
            f"  {rationale}",
            "",
        ]

        if verdict == "LIKELY_PATCHED":
            out += [
                "── DO THIS INSTEAD ──",
                "  1. Verify the deployed version independently — a header or a",
                "     package.json is a claim, not proof. Check a build artifact.",
                "  2. If the version is genuinely fixed, record a documented negative",
                "     (record_probe_outcome) so the tuple is not re-tested, and move on.",
                "  3. Look for the same bug CLASS elsewhere in the app rather than",
                "     re-testing this CVE — a patched dependency says nothing about",
                "     first-party code with the same pattern.",
                "",
            ]
            return "\n".join(out)

        axes = list(_ECOSYSTEM_AXES.get(eco, []))
        axes += _GENERIC_AXES
        out.append(f"── WHAT BREAKS A CROSS-VERSION PoC HERE ({eco or 'generic'}) ──")
        out.append("  Work top-down. Each is a shape change, not a different vulnerability —")
        out.append("  a clean 4xx means you got the envelope wrong, not that the target is safe.")
        for i, axis in enumerate(axes[:8], 1):
            out.append(f"  {i}. {axis}")
        out.append("")

        out.append("── HOW TO TELL 'WRONG ENVELOPE' FROM 'NOT VULNERABLE' ──")
        out += [
            "  400 / 404 / clean validation error  -> envelope wrong. Adapt and retry.",
            "  500 / stack trace / parser error    -> reaching the sink. Refine the payload.",
            "  Timing delta or OOB callback        -> vulnerable even with no visible output.",
            "  200 with the payload echoed inert   -> reached, but neutralized. Change context, not payload.",
            "  Identical response to baseline      -> not reaching the handler at all. Re-check the route.",
            "",
        ]

        cls = (vuln_class or _ECOSYSTEM_TO_CLASS.get(eco, "")).strip()
        out.append("── NEXT CALLS ──")
        if target_url and (cve_id or cls):
            out.append(
                f"  probe_cve_with_variants(cve_id={cve_id or '(alias)'!r}, "
                f"target_url={target_url!r}"
                + (f", vuln_class={cls!r}" if cls else "")
                + (f", baseline_payload={poc_payload[:80]!r}" if poc_payload else "")
                + ")"
            )
            out.append("     ^ sweeps the modelled envelope shapes for this class, first-CONFIRMED short-circuits.")
        if eco in ("nextjs", "react"):
            out.append(
                "  smart_js_analyze(...)  # harvest the LIVE Server Action id — "
                "never reuse the id embedded in a published PoC."
            )
        if not target_version:
            out.append("  detect_tech_stack(...)  # required — the verdict above is UNKNOWN without it.")
        if poc_payload:
            out.append(
                f"  mutate_payload(payload={poc_payload[:60]!r}, ...)  # encoding-layer axis"
            )
        out.append("  record_probe_outcome(...)  # log the adapted attempt, pass or fail, so the next round starts here.")
        out.append("")

        out.append("── CONFIRM THE REASONING (last, not first) ──")
        out.append("  Read these to check the shape delta between the two versions —")
        out.append("  the changelog entry and the fix commit tell you what moved.")
        seed = component.replace(" ", "+")
        if poc_version and target_version:
            out.append(f"  WebSearch  \"{component} changelog {poc_version} {target_version} breaking changes\"")
        out.append(f"  WebSearch  \"{component} {cve_id or vuln_class} patch commit diff\"")
        out.append(f"  WebFetch   https://github.com/search?q={seed}+{cve_id or 'security+fix'}&type=commits")
        out.append("")
        out.append(
            "  Budget: 2 sources. If the delta is not clear after those, derive it "
            "from the target's own behaviour — probe the envelope axes above and "
            "read the error surface. The running application is the authority."
        )
        return "\n".join(out)
