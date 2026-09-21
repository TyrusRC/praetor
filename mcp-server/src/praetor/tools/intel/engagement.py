"""Engagement-narrative graph — MCP tools.

Records the pre-finding lineage (goal → intent → fact → finding → asset) that
Praetor's finding stores don't capture, using the same vocabulary as
`howmp/dsh-pentest` so the two interoperate on DeepSeek Harness. Storage is
`.burp-intel/<domain>/engagement.json`; the pure graph logic is in `_engagement.py`.

Flow: `record_goal` (once) → `record_intent` / `record_fact` as you hunt →
`save_finding` (the gated pipeline, unchanged) then `link_finding` to hang the proof
on the intent that earned it → `engagement_graph` to read it back (text / mermaid /
json / dsh replay).
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from . import _engagement as E
from ._internals import _atomic_write_json, _intel_path


def _graph_path(domain: str):
    return _intel_path(domain) / "engagement.json"


def _load(domain: str) -> dict | None:
    p = _graph_path(domain)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(domain: str, graph: dict) -> None:
    _atomic_write_json(_graph_path(domain), graph)


def _finding_meta(domain: str, finding_id: str) -> dict | None:
    """Look up a saved finding's title/severity/repro from findings.json (or None)."""
    p = _intel_path(domain) / "findings.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    items = data if isinstance(data, list) else data.get("findings", [])
    for f in items:
        if isinstance(f, dict) and str(f.get("id") or f.get("finding_id")) == finding_id:
            return f
    return None


def _apply(domain: str, mutator) -> str:
    """Load the graph (guarding "no goal yet"), run mutator(graph) -> result string,
    save, and return the result — or an operator-readable error. The load/guard/save
    boilerplate every mutating tool shares."""
    graph = _load(domain)
    if graph is None:
        return "error: no engagement graph — call record_goal first"
    try:
        result = mutator(graph)
        _save(domain, graph)
        return result
    except (ValueError, OSError) as exc:
        return f"error: {exc}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def record_goal(domain: str, target: str, objective: str,
                          authorization: str = "") -> str:
        """Start (or RESET) the engagement graph for a domain — the single anchor.

        Creates goal-1 with the target, objective, and an optional authorization note
        (SoW / written-approval reference — audit metadata, not a gate). Calling it
        again resets the whole graph. This is the pre-finding lineage layer; the
        save-finding pipeline is unchanged and remains the source of truth for vulns.

        Args:
            domain: target the graph belongs to (its .burp-intel dir).
            target: what is in scope (host / app / range).
            objective: the engagement goal (e.g. 'prove auth bypass + PII access').
            authorization: SoW / approval reference to stamp into the report.
        """
        try:
            graph = E.new_graph(target, objective, authorization)
            _save(domain, graph)
        except (ValueError, OSError) as exc:
            return f"error: {exc}"
        return f"goal-1 set for {domain}: {target} — {objective}\n" + E.render_text(graph)

    @mcp.tool()
    async def record_intent(domain: str, title: str, parent: str = "goal-1") -> str:
        """Record a hypothesis / planned action (an 'intent') to pursue.

        Anchored to the goal (default) or to a fact — pass a `fact-<n>` id as parent
        when an observation suggested this follow-up (a derived_from link). Returns
        the new intent id to reference from `record_fact` / `link_finding`.

        Args:
            domain: target domain.
            title: the hypothesis/action, e.g. 'test IDOR on order_id'.
            parent: 'goal-1' (default) or a `fact-<n>` id this intent follows from.
        """
        def m(g):
            iid = E.add_intent(g, title, parent)
            return f"{iid}: {title}  (⇐ {parent})"
        return _apply(domain, m)

    @mcp.tool()
    async def record_fact(domain: str, text: str, intent: str) -> str:
        """Record an observation an intent yielded (a baseline delta, error, route).

        Args:
            domain: target domain.
            text: the observation, e.g. '/api/users?id= returns 500 on a quote'.
            intent: the `intent-<n>` that produced it.
        """
        def m(g):
            fid = E.add_fact(g, text, intent)
            return f"{fid} (⇐ {intent}): {text}"
        return _apply(domain, m)

    @mcp.tool()
    async def record_asset(domain: str, name: str, atype: str = "",
                           parent: str = "") -> str:
        """Record a target resource (host / service / endpoint / account) in the asset
        tree. Optional `parent` (an `asset-<n>` id) nests it; empty = a root asset.

        Args:
            domain: target domain.
            name: the resource, e.g. 'acme.tld' or '/api/v1/orders'.
            atype: host / service / endpoint / account / bucket / ... (free text).
            parent: an existing `asset-<n>` to nest under, or '' for a root.
        """
        def m(g):
            aid = E.add_asset(g, name, atype, parent)
            tail = f"  (⇐ {parent})" if parent else ""
            return f"{aid}: {name} [{atype or '?'}]{tail}"
        return _apply(domain, m)

    @mcp.tool()
    async def link_finding(domain: str, finding_id: str, intent: str,
                           assets: list[str] | None = None, title: str = "") -> str:
        """Hang a SAVED finding on the intent that proved it (a proves edge) + assets.

        Call AFTER `save_finding` (which returns the finding id) — this does not
        create or gate a finding, it only records the lineage. Title / severity /
        reproduction steps are pulled from findings.json when present, so the graph
        and the dsh replay carry real finding data.

        Args:
            domain: target domain.
            finding_id: the saved findings.json id (e.g. 'f007').
            intent: the `intent-<n>` this finding proves.
            assets: `asset-<n>` ids the finding affects (optional).
            title: override title; default reads it from findings.json.
        """
        meta = _finding_meta(domain, finding_id) or {}
        severity = str(meta.get("severity", "")).lower()
        repro = meta.get("reproduction_steps") or meta.get("reproductionSteps") or []
        use_title = title.strip() or str(meta.get("title", "")) or finding_id

        def m(g):
            nid = E.add_finding(g, finding_id, use_title, intent,
                                assets=assets or [], severity=severity,
                                repro=repro if isinstance(repro, list) else [])
            warn = "" if meta else "  (note: finding not found in findings.json — save it first)"
            return f"{nid} proves←{intent}: {use_title} [{severity or '?'}]{warn}"
        return _apply(domain, m)

    @mcp.tool()
    async def engagement_graph(domain: str, format: str = "text") -> str:
        """Read back the engagement lineage — the goal→intent→fact→finding→asset graph.

        Formats:
          - text     : indented lineage summary (default).
          - mermaid  : a Mermaid flowchart (paste into any Markdown renderer).
          - json     : the raw graph (nodes + typed edges).
          - dsh      : an ordered `pentest_add_*` replay so the DeepSeek-Harness agent
                       mirrors this graph into dsh-pentest's live view (Praetor = the
                       moves, dsh-pentest = the map).

        Args:
            domain: target domain.
            format: text | mermaid | json | dsh.
        """
        graph = _load(domain)
        if graph is None:
            return "error: no engagement graph — call record_goal first"
        fmt = (format or "text").lower()
        if fmt == "mermaid":
            return E.render_mermaid(graph)
        if fmt == "json":
            return json.dumps(graph, indent=2, default=str)
        if fmt == "dsh":
            return json.dumps(E.render_dsh(graph), indent=2, default=str)
        return E.render_text(graph)
