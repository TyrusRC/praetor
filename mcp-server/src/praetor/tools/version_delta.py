"""`adapt_poc_to_version` — turn a PoC for version A into candidates for version B.

Version/ecosystem helpers live in _version_helpers; this is the tool + register.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._version_helpers import (  # noqa: F401
    parse_version, compare_versions, version_distance, detect_ecosystem,
    assess_applicability, _GENERIC_AXES, _ECOSYSTEM_AXES, _ECOSYSTEM_TO_CLASS,
)


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
