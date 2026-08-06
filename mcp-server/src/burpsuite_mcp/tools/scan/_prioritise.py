"""Order the knowledge base by relevance before the probe budget cuts it off.

The orchestrator walks the knowledge list in order and stops at
`max_probes_per_param`. With ~1585 probes and a budget of 20, the order decides
everything and the list order was arbitrary.

That had a specific, repeatable failure. A context may declare `param_match`
and `tech_match`, and the orchestrator uses them to SKIP non-matching contexts
— so a context declaring neither matches every parameter. Those unconstrained
contexts (clickjacking, session_security, crypto_weakness) sat early in the list
and consumed the entire budget, while `sqli/error_based`, which declares
`param_match: ["id", "uid", ...]`, was never reached. Probing an integer `id`
on a classic-ASP app sent 20 probes and not one of them was SQL injection.

Sorting here rather than in Java keeps the fix in one language and needs no
change to the orchestrator: it still consumes the list in order, the order is
just no longer accidental.
"""

from __future__ import annotations

# Rule 29: spend the budget where MEDIUM+ lives. Injection reaching a sink,
# authorization, authentication/session, and business logic are what programs
# pay for. Header/TLS/config classes are recon output — they are still probed,
# just never at the expense of a class that can produce a real finding.
_CLASS_VALUE: dict[str, int] = {}


def _tier(names: tuple[str, ...], score: int) -> None:
    for n in names:
        _CLASS_VALUE[n] = score


_tier((
    "sqli", "nosqli", "rce", "command_injection", "ssti", "ssrf", "xxe",
    "deserialization", "path_traversal", "lfi", "file_upload",
    "request_smuggling", "prototype_pollution", "graphql_injection",
), 6)
_tier((
    "idor", "bola", "bfla", "bopla", "access_control", "auth_bypass",
    "authentication", "authorization", "jwt", "oauth", "saml", "session",
    "mass_assignment", "business_logic", "race_condition", "privilege_escalation",
), 5)
_tier((
    "xss", "dom_xss", "csrf", "cache_poisoning", "cors", "open_redirect",
    "host_header", "graphql", "api_abuse", "websocket",
), 3)
_tier((
    "clickjacking", "session_security", "crypto_weakness", "ssl", "tls",
    "security_headers", "missing_headers", "info_disclosure", "cookie",
    "rate_limit", "version_disclosure",
), 0)

_DEFAULT_VALUE = 2


def class_value(category: str) -> int:
    """Impact tier for a knowledge category. Unknown classes sit mid-table."""
    cat = (category or "").lower()
    if cat in _CLASS_VALUE:
        return _CLASS_VALUE[cat]
    # Split files (`ssti_elixir`, `sqli_mssql`) inherit their parent's tier.
    for name, score in sorted(_CLASS_VALUE.items(), key=lambda kv: -len(kv[0])):
        if cat.startswith(name + "_") or cat.startswith(name):
            return score
    return _DEFAULT_VALUE


def _param_hit(param_match: list, params: set[str]) -> bool:
    """True when a declared param_match names one of the target parameters."""
    if not param_match or not params:
        return False
    for want in param_match:
        w = str(want).lower()
        if any(w == p or w in p or p in w for p in params):
            return True
    return False


def score_entry(kb: dict, params: set[str], tech: set[str]) -> tuple[int, int, str]:
    """Sort key for one knowledge file. Higher sorts first.

    Returns (targeting, value, category) — targeting dominates, because a class
    that declares it applies to this parameter is nearly always a better use of
    a probe than a high-value class that says nothing about where it applies.
    """
    category = str(kb.get("category") or "")
    targeting = 0
    universal = True

    for ctx in (kb.get("contexts") or {}).values():
        if not isinstance(ctx, dict):
            continue
        pm = ctx.get("param_match") or []
        tm = ctx.get("tech_match") or []
        if pm or tm:
            universal = False
        if _param_hit(pm, params):
            targeting = max(targeting, 4)
        if tm and tech and any(str(t).lower() in tech for t in tm):
            targeting = max(targeting, targeting + 2 if targeting else 2)

    # A context constrained to OTHER parameters/stacks will be skipped by the
    # orchestrator anyway, so it costs nothing to rank it low. An unconstrained
    # context matches everything, which is exactly why it must not lead: it
    # would spend the budget before any targeted class is reached.
    if universal:
        targeting = -1

    return (targeting, class_value(category), category)


def target_tech_stack(domain: str) -> list[str]:
    """Detected tech for a domain from saved recon, or [] when unknown.

    Best-effort: an unknown stack costs ranking precision, never correctness —
    tech_match only ever raises a score, so a missing profile leaves the
    parameter-name signal to do the work.
    """
    if not domain:
        return []
    try:
        import json

        from burpsuite_mcp.tools.intel import _intel_path

        path = _intel_path(domain) / "profile.json"
        if not path.exists():
            return []
        profile = json.loads(path.read_text(encoding="utf-8"))
        stack = profile.get("tech_stack") or []
        return [str(t) for t in stack] if isinstance(stack, list) else []
    except Exception:
        return []


def prioritise(knowledge: list[dict], targets: list[dict], tech_stack=None) -> list[dict]:
    """Reorder knowledge files most-relevant-first for this set of targets.

    Scored against the union of the targets' parameters. Per-target ordering
    would be sharper, but the orchestrator takes one list for the whole call and
    skips contexts whose `param_match` misses the parameter it is currently on —
    so a file ranked high for one target costs nothing on the others.
    """
    params = {
        str(t.get("parameter") or "").lower()
        for t in targets or []
        if isinstance(t, dict) and t.get("parameter")
    }
    tech = {str(t).lower() for t in (tech_stack or [])}
    return sorted(knowledge, key=lambda kb: score_entry(kb, params, tech), reverse=True)
