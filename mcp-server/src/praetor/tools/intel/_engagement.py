"""Engagement-narrative graph — pure core.

Praetor's finding stores (findings.json / coverage.json / notes) capture WHAT was
proven, but not the pre-finding lineage: which hypothesis led to which observation
led to which proof. This models that lineage with the SAME vocabulary as
`howmp/dsh-pentest` so the two interoperate on DeepSeek Harness (Praetor = the
moves, dsh-pentest = the map):

    goal --spawns--> intent --yields--> fact --derived_from--> intent
    intent --proves--> finding        asset --parent--> asset

Nodes get deterministic ids `<kind>-<n>` (per-domain counter). Every add validates
its references (reference rejection) — you cannot yield a fact from an intent that
doesn't exist. All functions here are pure: they take and return the graph dict (or
raise ValueError with an operator-readable message); the tool layer does load/save.
"""

from __future__ import annotations

from datetime import datetime, timezone

GOAL_ID = "goal-1"
_KINDS = ("intent", "fact", "finding", "asset")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_graph(target: str, objective: str, authorization: str = "") -> dict:
    """A fresh engagement graph anchored on one goal (resets any prior graph)."""
    return {
        "version": 1,
        "goal": {
            "id": GOAL_ID,
            "kind": "goal",
            "target": target.strip(),
            "objective": objective.strip(),
            "authorization": authorization.strip(),
            "created": _now(),
        },
        "counters": {k: 0 for k in _KINDS},
        "nodes": {},
        "edges": [],
    }


def _next_id(graph: dict, kind: str) -> str:
    graph["counters"][kind] = graph["counters"].get(kind, 0) + 1
    return f"{kind}-{graph['counters'][kind]}"


def _require(graph: dict, node_id: str, kinds: tuple[str, ...]) -> dict:
    """Return the node, or raise if it's missing / the wrong kind (ref rejection)."""
    if node_id == GOAL_ID and "goal" in kinds:
        return graph["goal"]
    node = graph.get("nodes", {}).get(node_id)
    if node is None:
        raise ValueError(f"unknown node {node_id!r} — add it first")
    if node["kind"] not in kinds:
        raise ValueError(f"{node_id!r} is a {node['kind']}, expected {' or '.join(kinds)}")
    return node


def add_intent(graph: dict, title: str, parent: str = GOAL_ID) -> str:
    """A hypothesis / planned action. Anchored to the goal (spawns) or, when parent
    is a fact, to that observation (derived_from — a follow-up the fact suggests)."""
    if not title.strip():
        raise ValueError("intent title is required")
    parent_node = _require(graph, parent, ("goal", "fact"))
    iid = _next_id(graph, "intent")
    graph["nodes"][iid] = {"id": iid, "kind": "intent", "title": title.strip(),
                           "parent": parent, "status": "open"}
    # Anchored to the goal => spawns; anchored to a fact => derived_from (a follow-up).
    edge = "spawns" if parent_node["kind"] == "goal" else "derived_from"
    graph["edges"].append({"type": edge, "from": parent, "to": iid})
    return iid


def add_fact(graph: dict, text: str, intent: str) -> str:
    """An observation an intent yielded (a baseline delta, an error string, a route)."""
    if not text.strip():
        raise ValueError("fact text is required")
    _require(graph, intent, ("intent",))
    fid = _next_id(graph, "fact")
    graph["nodes"][fid] = {"id": fid, "kind": "fact", "text": text.strip(), "intent": intent}
    graph["edges"].append({"type": "yields", "from": intent, "to": fid})
    return fid


def add_finding(graph: dict, finding_id: str, title: str, intent: str,
                assets: list[str] | None = None, severity: str = "",
                repro: list[str] | None = None) -> str:
    """A proof (references a saved findings.json id) an intent proved; may affect assets."""
    if not finding_id.strip():
        raise ValueError("finding_id is required (the saved findings.json id)")
    _require(graph, intent, ("intent",))
    assets = assets or []
    for a in assets:
        _require(graph, a, ("asset",))
    nid = _next_id(graph, "finding")
    graph["nodes"][nid] = {"id": nid, "kind": "finding", "finding_id": finding_id.strip(),
                           "title": title.strip(), "intent": intent, "assets": list(assets),
                           "severity": severity, "repro": list(repro or [])}
    graph["edges"].append({"type": "proves", "from": intent, "to": nid})
    for a in assets:
        graph["edges"].append({"type": "affects", "from": nid, "to": a})
    return nid


def add_asset(graph: dict, name: str, atype: str = "", parent: str = "") -> str:
    """A target resource (host / service / endpoint / account). Optional parent asset
    builds the asset tree; empty parent = a root asset."""
    if not name.strip():
        raise ValueError("asset name is required")
    parent = parent.strip()
    if parent:
        _require(graph, parent, ("asset",))
    aid = _next_id(graph, "asset")
    graph["nodes"][aid] = {"id": aid, "kind": "asset", "name": name.strip(),
                           "atype": atype.strip(), "parent": parent or None}
    if parent:
        graph["edges"].append({"type": "parent", "from": parent, "to": aid})
    return aid


def _nodes_of(graph: dict, kind: str) -> list[dict]:
    return [n for n in graph.get("nodes", {}).values() if n["kind"] == kind]


def render_text(graph: dict) -> str:
    g = graph.get("goal", {})
    lines = [f"GOAL {g.get('id')}: {g.get('target','?')} — {g.get('objective','?')}"]
    if g.get("authorization"):
        lines.append(f"  authorization: {g['authorization']}")
    counts = {k: len(_nodes_of(graph, k)) for k in _KINDS}
    lines.append(f"  {counts['intent']} intents · {counts['fact']} facts · "
                 f"{counts['finding']} findings · {counts['asset']} assets")
    for it in sorted(_nodes_of(graph, "intent"), key=lambda n: n["id"]):
        lines.append(f"\n[{it['id']}] intent: {it['title']}  ({it['status']}, ⇐ {it['parent']})")
        for f in sorted(_nodes_of(graph, "fact"), key=lambda n: n["id"]):
            if f["intent"] == it["id"]:
                lines.append(f"    yields  {f['id']}: {f['text']}")
        for fn in sorted(_nodes_of(graph, "finding"), key=lambda n: n["id"]):
            if fn["intent"] == it["id"]:
                sev = f" [{fn['severity']}]" if fn.get("severity") else ""
                aff = f"  affects {', '.join(fn['assets'])}" if fn.get("assets") else ""
                lines.append(f"    PROVES  {fn['id']} → {fn['finding_id']}{sev}: {fn['title']}{aff}")
    assets = sorted(_nodes_of(graph, "asset"), key=lambda n: n["id"])
    if assets:
        lines.append("\nassets:")
        for a in assets:
            tail = f" (⇐ {a['parent']})" if a.get("parent") else ""
            lines.append(f"  {a['id']}: {a['name']} [{a.get('atype') or '?'}]{tail}")
    return "\n".join(lines)


def render_mermaid(graph: dict) -> str:
    """A Mermaid flowchart of the lineage — pasteable into any Markdown renderer."""
    out = ["```mermaid", "flowchart TD"]
    g = graph.get("goal", {})
    # Node ids must match the edge refs, which sanitise "-" -> "_".
    out.append(f'  {GOAL_ID.replace("-", "_")}["🎯 {g.get("target","goal")}"]')
    shape = {"intent": ('["', '"]'), "fact": ('("', '")'),
             "finding": ('{{"', '"}}'), "asset": ('[/"', '"/]')}
    for n in graph.get("nodes", {}).values():
        lb, rb = shape[n["kind"]]
        label = n.get("title") or n.get("text") or n.get("name") or n.get("finding_id") or n["id"]
        label = str(label).replace('"', "'")[:60]
        out.append(f'  {n["id"].replace("-", "_")}{lb}{label}{rb}')
    for e in graph.get("edges", []):
        out.append(f'  {e["from"].replace("-", "_")} -->|{e["type"]}| {e["to"].replace("-", "_")}')
    out.append("```")
    return "\n".join(out)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


def render_report(graph: dict) -> str:
    """A Markdown engagement report from the lineage — the pentest_report analog:
    findings (with the intent that proved them, affected assets, reproducible steps),
    the exploration narrative, and the asset tree. Complements the finding-centric
    generate_report; this one tells the goal→proof story."""
    g = graph.get("goal", {})
    intents = {n["id"]: n for n in _nodes_of(graph, "intent")}
    assets = {n["id"]: n for n in _nodes_of(graph, "asset")}
    out = [f"# Engagement — {g.get('target', '?')}", ""]
    out.append(f"**Objective:** {g.get('objective', '?')}")
    out.append(f"**Authorization:** {g.get('authorization') or '—'}")
    out.append("")

    findings = sorted(_nodes_of(graph, "finding"),
                      key=lambda n: (_SEV_ORDER.get(n.get("severity", ""), 5), n["id"]))
    out.append("## Findings")
    if not findings:
        out.append("\n_None proven yet._")
    for fn in findings:
        sev = (fn.get("severity") or "unrated").upper()
        out.append(f"\n### {fn['finding_id']} — {fn.get('title') or fn['finding_id']}  [{sev}]")
        it = intents.get(fn.get("intent"))
        if it:
            out.append(f"- **Proven by:** {it['id']} — {it['title']}")
        aff = [assets[a]["name"] for a in fn.get("assets", []) if a in assets]
        out.append(f"- **Affects:** {', '.join(aff) if aff else '—'}")
        repro = fn.get("repro") or []
        if repro:
            out.append("- **Reproducible steps:**")
            out.extend(f"  {i}. {step}" for i, step in enumerate(repro, 1))
        else:
            out.append("- **Reproducible steps:** _not recorded — see the saved finding_")

    out.append("\n## Exploration lineage")
    for it in sorted(intents.values(), key=lambda n: n["id"]):
        out.append(f"\n- **{it['id']}** {it['title']} _({it['status']})_")
        for f in sorted(_nodes_of(graph, "fact"), key=lambda n: n["id"]):
            if f["intent"] == it["id"]:
                out.append(f"  - yields {f['id']}: {f['text']}")
        for fn in findings:
            if fn.get("intent") == it["id"]:
                out.append(f"  - **proves** {fn['finding_id']}: {fn.get('title') or ''}")

    tree = sorted(assets.values(), key=lambda n: n["id"])
    if tree:
        out.append("\n## Assets")
        depth = {}
        for a in tree:
            d = 0
            p = a.get("parent")
            seen = set()
            while p and p in assets and p not in seen:
                seen.add(p)
                d += 1
                p = assets[p].get("parent")
            depth[a["id"]] = d
            out.append(f"{'  ' * d}- {a['name']} [{a.get('atype') or '?'}]")
    return "\n".join(out)


def render_dsh(graph: dict) -> list[dict]:
    """A replay the dsh agent runs to mirror this graph into dsh-pentest's live view.

    Each item is a {tool, args} for a dsh-pentest `pentest_add_*` call, in dependency
    order (goal → assets → intents → facts → findings). dsh assigns its own ids on
    each add; the agent maps them by running the calls in order.
    """
    calls: list[dict] = []
    g = graph.get("goal", {})
    calls.append({"tool": "pentest_add_goal", "args": {
        "target": g.get("target", ""), "objective": g.get("objective", ""),
        "authorization": g.get("authorization", "")}})
    for a in sorted(_nodes_of(graph, "asset"), key=lambda n: n["id"]):
        calls.append({"tool": "pentest_add_asset", "args": {
            "name": a["name"], "atype": a.get("atype", ""),
            "parentRef": a.get("parent") or ""}})
    for it in sorted(_nodes_of(graph, "intent"), key=lambda n: n["id"]):
        calls.append({"tool": "pentest_add_intent",
                      "args": {"goalId": GOAL_ID, "title": it["title"], "ref": it["id"]}})
    for f in sorted(_nodes_of(graph, "fact"), key=lambda n: n["id"]):
        calls.append({"tool": "pentest_add_fact",
                      "args": {"intentRef": f["intent"], "text": f["text"]}})
    for fn in sorted(_nodes_of(graph, "finding"), key=lambda n: n["id"]):
        calls.append({"tool": "pentest_add_finding", "args": {
            "intentRef": fn["intent"], "title": fn["title"] or fn["finding_id"],
            "severity": fn.get("severity", ""),
            "reproducibleSteps": fn.get("repro") or ["see Praetor finding " + fn["finding_id"]],
            "assetRefs": fn.get("assets", [])}})
    return calls
