"""pick_tool: keyword -> MCP tool resolver (logic; data in _pick_data.py)."""

from ._pick_data import _MAPPINGS, TIER1_HUNT_LOOP

__all__ = ["_MAPPINGS", "TIER1_HUNT_LOOP", "pick_tool_impl"]



def _match_specificity(keyword: str) -> int:
    """Specificity weight of a matched keyword.

    Multi-word anchors ("csrf token", "cve-2026-32879") are far more specific
    than bare words ("token", "cve-2") and must win. Weight = word-count * 10
    + character length, so a 3-word anchor always outranks a 1-word substring
    no matter how long the latter is.
    """
    return len(keyword.split()) * 10 + len(keyword)


def _score_mappings(task_lower: str):
    """Rank matching mappings by best-matched-keyword specificity, best-first.

    Used only to surface *alternatives* — the primary pick stays first-match so
    the hand-ranked _MAPPINGS order (jwt before header, specific-CVE before the
    generic cve-2 fallback) is preserved verbatim. Ranking alternatives by
    specificity means a genuinely more-specific route (multi-word anchor) is
    offered ahead of a generic one regardless of its position in the list.
    Returns (score, -index, tool, example) tuples.
    """
    scored = []
    for idx, (keywords, tool, example) in enumerate(_MAPPINGS):
        best = max(
            (_match_specificity(kw) for kw in keywords if kw in task_lower),
            default=0,
        )
        if best > 0:
            scored.append((best, -idx, tool, example))
    scored.sort(reverse=True)
    return scored


async def pick_tool_impl(task: str) -> str:
    task_lower = task.lower()

    # Primary pick: first-match (unchanged) preserves hand-ranked priority.
    primary = None
    for keywords, tool, example in _MAPPINGS:
        if any(kw in task_lower for kw in keywords):
            primary = (tool, example)
            break

    if primary is not None:
        tool, example = primary
        out = [f"Use: {tool}", f"Example: {example}"]
        # Surface up to 2 distinct specificity-ranked runners-up so the model
        # can course-correct when the top route is wrong — cheaper than
        # re-querying, and directly counters first-match shadowing.
        alts, seen = [], {tool}
        for _s, _i, alt_tool, alt_example in _score_mappings(task_lower):
            if alt_tool in seen:
                continue
            seen.add(alt_tool)
            alts.append(f"  - {alt_tool}: {alt_example}")
            if len(alts) == 2:
                break
        if alts:
            out.append("Alternatives:")
            out.extend(alts)
        return "\n".join(out)

    # Tier-1 fallback — list the core hunt-loop tools so the model can pick
    # one rather than blindly searching the 300+ tool surface.
    tier1_list = "\n".join(f"  - {name}: {desc}" for name, desc in TIER1_HUNT_LOOP[:12])
    return (
        f"No direct match for '{task}'. Tier-1 hunt-loop entry points:\n"
        f"{tier1_list}\n"
        f"  ... ({len(TIER1_HUNT_LOOP)} total — see list_tier1_tools())\n\n"
        f"Default chain: load_target_intel → discover_attack_surface → auto_probe."
    )
