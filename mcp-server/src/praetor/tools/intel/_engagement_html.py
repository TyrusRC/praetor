"""Tabbed engagement view — the self-contained HTML page builder.

`engagement_graph(domain, format='html')` calls `render_engagement_html` here.
The centerpiece is an INTERACTIVE cytoscape.js security graph with a layout
toggle: Flow (dagre left-to-right exploration chain — the dsh-pentest flow look,
default) or Force (fcose Wiz-Security-Graph blob). Both layouts + dagre come from
jsdelivr (the only external resources). OPERATIONS are included: every read_oplog
action becomes an ATT&CK-tagged node edged to the asset it acted on.

The header carries count chips (Intents · Facts · Findings · Assets · Operations).
Tabs: Security Graph (default) · Operations (oplog + loot timeline) · Findings(N) ·
Assets(N) (the asset tree) · Report. Reuses the dark theme + markdown renderer
from report/_html and the graph model / render_report from _engagement. UI is
English-only.

Graph node/edge data is embedded as JSON and rendered on a canvas by cytoscape
(labels are canvas text, not HTML — no injection). The detail panel builds its
rows with textContent, and every value in the HTML tabs is html.escape'd: oplog
commands, finding titles, asset names and targets carry attacker/target strings
and must never execute.
"""

from __future__ import annotations

import html
import json

from praetor.tools.redteam._oplog import attack_for, read_loot, read_oplog
from praetor.tools.report._html import _CSS_DARK, markdown_to_html

from . import _engagement as E

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unrated": 5, "": 5}
_SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}

_GOAL = E.GOAL_ID

# Reuse the dark theme palette, minus the now-unused .mermaid selectors — this
# view renders the graph with cytoscape, so those rules would be dead CSS.
_CSS_BASE = "\n".join(
    ln for ln in _CSS_DARK.splitlines() if not ln.lstrip().startswith(".mermaid"))


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _trunc(s: str, n: int = 240) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + " …"


def _sev_badge(sev: str) -> str:
    s = (sev or "").lower()
    cls = _SEV_CLASS.get(s, "unrated")
    return f'<span class="badge sev-{cls}">{_esc((sev or "unrated").upper())}</span>'


# ---------------------------------------------------------------- graph model

def _node(graph: dict, nid: str) -> dict | None:
    if nid == _GOAL:
        return graph.get("goal")
    return graph.get("nodes", {}).get(nid)


def _attack_path(graph: dict) -> tuple[set, set]:
    """The goal→…→finding→asset paths (Wiz 'toxic-combination' highlight).

    Returns (node_ids, edge_pairs) to emphasise. Walks each finding back through
    its intent, following derived_from/yields hops up to the goal; cycle-guarded.
    """
    nodes = graph.get("nodes", {})
    hit_n: set = set()
    hit_e: set = set()
    for fn in E._nodes_of(graph, "finding"):
        hit_n.add(fn["id"])
        intent_id = fn.get("intent")
        hit_e.add((intent_id, fn["id"]))          # proves
        for a in fn.get("assets", []):
            hit_e.add((fn["id"], a))               # affects
            hit_n.add(a)
        cur = intent_id
        guard: set = set()
        while cur and cur in nodes and cur not in guard:
            guard.add(cur)
            hit_n.add(cur)
            parent = nodes[cur].get("parent")
            if parent == _GOAL:
                hit_e.add((_GOAL, cur))            # spawns
                hit_n.add(_GOAL)
                break
            if parent and parent in nodes:         # parent is a fact
                hit_e.add((parent, cur))           # derived_from
                hit_n.add(parent)
                fi = nodes[parent].get("intent")
                if fi:
                    hit_e.add((fi, parent))        # yields
                cur = fi
            else:
                break
    return hit_n, hit_e


def _match_asset(target: str, assets: list[dict]) -> str | None:
    """The asset an operation acted on — target host/name matched either way."""
    t = (target or "").strip().lower()
    if not t:
        return None
    for a in assets:
        name = (a.get("name") or "").strip().lower()
        if name and (name in t or t in name):
            return a["id"]
    return None


def _build_elements(graph: dict, oplog: list[dict], loot: list[dict]) -> list[dict]:
    g = graph.get("goal", {})
    intents = {n["id"]: n for n in E._nodes_of(graph, "intent")}
    assets_l = E._nodes_of(graph, "asset")
    assets = {n["id"]: n for n in assets_l}
    hit_n, hit_e = _attack_path(graph)
    loot_by_op: dict[str, list[dict]] = {}
    for row in loot:
        loot_by_op.setdefault(row.get("oplog_id") or "", []).append(row)

    els: list[dict] = []

    def cls(nid: str) -> str:
        return "path" if nid in hit_n else ""

    # goal
    els.append({"data": {"id": _GOAL, "kind": "goal",
                         "label": g.get("target") or "goal",
                         "objective": g.get("objective", ""),
                         "authorization": g.get("authorization", "")},
                "classes": cls(_GOAL)})
    # intents
    for it in intents.values():
        els.append({"data": {"id": it["id"], "kind": "intent",
                             "label": _trunc(it.get("title", ""), 48),
                             "title": it.get("title", ""), "status": it.get("status", "")},
                    "classes": cls(it["id"])})
    # facts
    for f in E._nodes_of(graph, "fact"):
        els.append({"data": {"id": f["id"], "kind": "fact",
                             "label": _trunc(f.get("text", ""), 42),
                             "text": f.get("text", "")},
                    "classes": cls(f["id"])})
    # assets
    for a in assets_l:
        els.append({"data": {"id": a["id"], "kind": "asset",
                             "label": _trunc(a.get("name", ""), 40),
                             "name": a.get("name", ""), "atype": a.get("atype", "")},
                    "classes": cls(a["id"])})
    # findings (severity-tinted)
    for fn in E._nodes_of(graph, "finding"):
        sev = (fn.get("severity") or "").lower()
        it = intents.get(fn.get("intent"))
        aff = [assets[a]["name"] for a in fn.get("assets", []) if a in assets]
        els.append({"data": {"id": fn["id"], "kind": "finding",
                             "sev": _SEV_CLASS.get(sev, "unrated"),
                             "label": _trunc(fn.get("finding_id") or fn["id"], 24),
                             "finding_id": fn.get("finding_id", ""),
                             "title": fn.get("title", ""),
                             "severity": (fn.get("severity") or "unrated").upper(),
                             "proven_by": (it.get("title") if it else ""),
                             "affects": ", ".join(aff),
                             "steps": list(fn.get("repro") or [])},
                    "classes": "finding path"})
    # graph edges
    for e in graph.get("edges", []):
        pair = (e.get("from"), e.get("to"))
        els.append({"data": {"id": f'e-{e.get("from")}-{e.get("to")}-{e.get("type")}',
                             "source": e.get("from"), "target": e.get("to"),
                             "label": e.get("type", "")},
                    "classes": "path" if pair in hit_e else ""})

    # OPERATIONS — each oplog action a node, edged to the asset it acted on (else goal)
    for i, entry in enumerate(oplog):
        oid = entry.get("id") or f"op-{i+1}"
        tech = entry.get("technique") or ""
        name = entry.get("technique_name") or (attack_for(entry.get("tool", ""))[2] if tech else "")
        ts = entry.get("start") or entry.get("timestamp") or entry.get("ts") or entry.get("recorded") or ""
        lt = loot_by_op.get(entry.get("id") or "", [])
        loot_lbl = [f'{r.get("id","")}:{r.get("type") or r.get("loot_type") or "?"}' for r in lt]
        label = tech or (entry.get("tool") or oid)
        els.append({"data": {"id": oid, "kind": "operation",
                             "label": _trunc(str(label), 22),
                             "tool": entry.get("tool", ""),
                             "command": entry.get("command", ""),
                             "target": entry.get("target", ""),
                             "technique": tech, "technique_name": name,
                             "ts": ts, "rc": entry.get("returncode"),
                             "tactic": entry.get("tactic", ""),
                             "loot": loot_lbl}})
        anchor = _match_asset(entry.get("target", ""), assets_l) or _GOAL
        els.append({"data": {"id": f"e-{oid}-{anchor}", "source": oid, "target": anchor,
                             "label": "acts_on"}, "classes": "op-edge"})
    return els


# ------------------------------------------------------------- HTML tab panels

def _findings_panel(graph: dict) -> str:
    intents = {n["id"]: n for n in E._nodes_of(graph, "intent")}
    assets = {n["id"]: n for n in E._nodes_of(graph, "asset")}
    findings = sorted(E._nodes_of(graph, "finding"),
                      key=lambda n: (_SEV_ORDER.get((n.get("severity") or "").lower(), 5), n["id"]))
    if not findings:
        return '<p class="empty">No findings linked to the graph yet — save_finding, then link_finding.</p>'
    out = []
    for fn in findings:
        title = fn.get("title") or fn.get("finding_id") or fn["id"]
        out.append('<div class="card">')
        out.append(f'<h3>{_sev_badge(fn.get("severity"))} '
                   f'<code>{_esc(fn.get("finding_id") or fn["id"])}</code> {_esc(title)}</h3>')
        it = intents.get(fn.get("intent"))
        if it:
            out.append(f'<div class="meta"><b>Proven by</b> {_esc(it["id"])} — {_esc(it["title"])}</div>')
        aff = [assets[a]["name"] for a in fn.get("assets", []) if a in assets]
        out.append(f'<div class="meta"><b>Affects</b> {_esc(", ".join(aff)) if aff else "—"}</div>')
        repro = fn.get("repro") or []
        if repro:
            steps = "".join(f"<li>{_esc(s)}</li>" for s in repro)
            out.append(f'<div class="meta"><b>Steps</b></div><ol>{steps}</ol>')
        out.append("</div>")
    return "\n".join(out)


def _operations_panel(oplog: list[dict], loot: list[dict]) -> str:
    loot_by_op: dict[str, list[dict]] = {}
    for row in loot:
        loot_by_op.setdefault(row.get("oplog_id") or "", []).append(row)
    if not oplog and not loot:
        return ('<p class="empty">No operator-log actions recorded — the OPERATIONS timeline '
                'fills as network/AD/post-ex tools run (record_action / run_network_tool).</p>')
    out: list[str] = []
    if oplog:
        out.append('<div class="tbl-wrap"><table class="ops"><thead><tr>'
                   "<th>Time</th><th>ATT&amp;CK</th><th>Tool</th><th>Command</th>"
                   "<th>Target</th><th>RC</th><th>Loot</th></tr></thead><tbody>")
        for e in oplog:
            ts = e.get("start") or e.get("timestamp") or e.get("ts") or e.get("recorded") or ""
            tech = e.get("technique") or ""
            name = e.get("technique_name") or (attack_for(e.get("tool", ""))[2] if tech else "")
            ttp = (f'<span class="badge ttp">{_esc(tech)}{" · " + _esc(name) if name else ""}</span>'
                   if tech else '<span class="meta">—</span>')
            rc = e.get("returncode")
            ops_loot = loot_by_op.get(e.get("id") or "", [])
            loot_cell = (f'<span class="loot-yes">● {len(ops_loot)}</span>' if ops_loot
                         else '<span class="meta">—</span>')
            out.append(
                "<tr>"
                f"<td>{_esc(ts)}</td>"
                f"<td>{ttp}</td>"
                f"<td><code>{_esc(e.get('tool'))}</code></td>"
                f"<td><code>{_esc(_trunc(e.get('command') or ''))}</code></td>"
                f"<td>{_esc(e.get('target') or '—')}</td>"
                f"<td>{_esc(rc) if rc is not None else '—'}</td>"
                f"<td>{loot_cell}</td>"
                "</tr>")
        out.append("</tbody></table></div>")
    out.append("<h2>Loot</h2>")
    if loot:
        out.append('<div class="tbl-wrap"><table class="ops"><thead><tr>'
                   "<th>ID</th><th>Type</th><th>Source</th><th>Via</th><th>From op</th></tr>"
                   "</thead><tbody>")
        for row in loot:
            src = row.get("source_host") or row.get("source") or ""
            out.append(
                "<tr>"
                f"<td><code>{_esc(row.get('id'))}</code></td>"
                f"<td>{_esc(row.get('type') or row.get('loot_type') or '?')}</td>"
                f"<td>{_esc(src or '—')}</td>"
                f"<td>{_esc(row.get('obtained_via') or '—')}</td>"
                f"<td>{_esc(row.get('oplog_id') or '—')}</td>"
                "</tr>")
        out.append("</tbody></table></div>")
    else:
        out.append('<p class="empty">No loot captured.</p>')
    return "\n".join(out)


def _assets_panel(graph: dict) -> str:
    """The asset tree (Assets tab) — roots with nested children, type-tagged."""
    assets = E._nodes_of(graph, "asset")
    if not assets:
        return '<p class="empty">No assets recorded — record_asset(name, atype, parent).</p>'
    amap = {a["id"]: a for a in assets}
    children: dict[str, list[dict]] = {}
    roots: list[dict] = []
    for a in assets:
        p = a.get("parent")
        if p and p in amap:
            children.setdefault(p, []).append(a)
        else:
            roots.append(a)

    def render(a: dict, seen: set) -> str:
        if a["id"] in seen:                      # cycle guard
            return ""
        seen.add(a["id"])
        atype = f'<span class="atype">[{_esc(a.get("atype") or "?")}]</span>'
        inner = f'<span class="adot"></span>{_esc(a.get("name") or a["id"])}{atype}'
        kids = children.get(a["id"], [])
        if kids:
            return f'<li>{inner}<ul>{"".join(render(c, seen) for c in kids)}</ul></li>'
        return f'<li>{inner}</li>'

    seen: set = set()
    items = "".join(render(a, seen) for a in roots)
    return f'<ul class="asset-tree">{items}</ul>'


_CHIP_SPEC = [
    ("intent", "Intents", "#4aa3ff"), ("fact", "Facts", "#586b7d"),
    ("finding", "Findings", "#ff5c6c"), ("asset", "Assets", "#1f9e8f"),
    ("operation", "Operations", "#b48ead"),
]


def _count_chips(counts: dict) -> str:
    """Header summary chips (Intents N · Facts N · Findings N · Assets N)."""
    chips = []
    for key, label, color in _CHIP_SPEC:
        n = counts.get(key, 0)
        if key == "operation" and not n:         # hide ops chip when none
            continue
        chips.append(
            f'<div class="chip"><span class="cdot" style="background:{color}"></span>'
            f'{label} <b>{n}</b></div>')
    return '<div class="chips">' + "".join(chips) + "</div>"


# ------------------------------------------------------------------ CSS / JS

_TAB_CSS = """
.tabs{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:6px;
  background:#0b0f14;border-bottom:1px solid var(--line);padding:10px 0 8px;margin-bottom:18px}
.tab{background:#161b22;color:var(--muted);border:1px solid var(--line);border-radius:6px;
  padding:7px 15px;font-size:.92em;cursor:pointer;font-family:inherit}
.tab:hover{color:var(--fg);border-color:var(--accent)}
.tab.active{color:#fff;background:var(--accent);border-color:var(--accent)}
.panel{display:none}
.panel.active{display:block}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.78em;
  font-weight:600;border:1px solid var(--line);white-space:nowrap}
.sev-crit{background:#3a1216;color:#ff8894;border-color:var(--crit)}
.sev-high{background:#3a2410;color:#ffb066;border-color:#ff8c42}
.sev-med{background:#3a3410;color:#f2d06b;border-color:#f2c94c}
.sev-low{background:#0f2740;color:#79c0ff;border-color:var(--accent)}
.sev-unrated{background:#161b22;color:var(--muted)}
.ttp{background:#101f16;color:#7ee2a8;border-color:#2ea06a}
.card{border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0;background:#0d1117}
.card h3{margin:.1em 0 .5em}
.meta{color:var(--muted);font-size:.9em;margin:.2em 0}
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
.ops td{font-size:.86em;vertical-align:top}
.ops code{white-space:pre-wrap;word-break:break-all}
.loot-yes{color:#7ee2a8}
.empty{color:var(--muted);font-style:italic;padding:18px 2px}
/* --- security graph canvas --- */
.graph-wrap{position:relative;width:100%;height:74vh;min-height:460px;border:1px solid var(--line);
  border-radius:10px;overflow:hidden;
  background:#070b10;
  background-image:linear-gradient(#0e1620 1px,transparent 1px),linear-gradient(90deg,#0e1620 1px,transparent 1px);
  background-size:34px 34px}
#cy{position:absolute;inset:0}
.gx{position:absolute;z-index:8;background:rgba(13,17,23,.92);border:1px solid var(--line);
  border-radius:8px;padding:10px 12px;font-size:.82em;backdrop-filter:blur(3px)}
.legend{top:12px;left:12px;max-width:190px}
.legend .row{display:flex;align-items:center;gap:7px;padding:2px 0;cursor:pointer;user-select:none}
.legend .row.off{opacity:.35}
.legend .dot{width:13px;height:13px;border-radius:4px;flex:0 0 auto;border:1px solid #0008}
.legend .dot.round{border-radius:50%}
.legend h4{margin:0 0 6px;font-size:.9em;color:#cdd9e5}
.detail{top:12px;right:12px;width:290px;max-width:66%;max-height:calc(74vh - 24px);overflow:auto;display:none}
.detail.show{display:block}
.detail h4{margin:0 0 6px;font-size:.98em;color:#cdd9e5;padding-right:18px}
.detail .k{color:var(--muted);font-size:.76em;text-transform:uppercase;letter-spacing:.4px;margin-top:8px}
.detail .v{color:var(--fg);font-size:.9em;word-break:break-word;white-space:pre-wrap}
.detail .close{position:absolute;top:8px;right:10px;cursor:pointer;color:var(--muted);font-size:1.1em}
.hint{bottom:12px;left:12px;color:var(--muted);font-size:.76em;background:none;border:none}
.cy-fail{padding:22px;color:#ff8894}
/* --- header count chips (intents/facts/findings/assets) --- */
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px}
.chip{display:inline-flex;align-items:center;gap:7px;background:#0d1117;border:1px solid var(--line);
  border-radius:20px;padding:4px 13px;font-size:.84em;color:var(--muted)}
.chip b{color:#e6edf3;font-size:1.08em}
.chip .cdot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.tab .cnt{color:var(--muted);font-size:.86em;margin-left:5px}
.tab.active .cnt{color:#dceaff}
/* --- graph layout toggle (Flow = dsh LR chain · Force = Wiz blob) --- */
.controls{bottom:12px;right:12px;display:flex;gap:4px;padding:5px}
.ctl-btn{background:#161b22;color:var(--muted);border:1px solid var(--line);border-radius:6px;
  padding:4px 12px;font-size:.8em;cursor:pointer;font-family:inherit}
.ctl-btn:hover{color:var(--fg);border-color:var(--accent)}
.ctl-btn.active{color:#fff;background:var(--accent);border-color:var(--accent)}
/* --- assets tab tree --- */
.asset-tree{list-style:none;padding-left:2px;line-height:1.9}
.asset-tree ul{list-style:none;padding-left:18px;border-left:1px solid var(--line);margin:2px 0 2px 5px}
.asset-tree li{padding:1px 0}
.asset-tree .atype{color:var(--muted);font-size:.82em;margin-left:7px}
.asset-tree .adot{display:inline-block;width:8px;height:8px;border-radius:2px;background:#1f9e8f;margin-right:7px}
"""

# Node palette by kind — deep navy canvas, Wiz-style typed nodes.
_STYLE = json.dumps([
    {"selector": "node", "style": {
        "label": "data(label)", "color": "#e6edf3", "font-size": 10, "font-family": "Segoe UI,Roboto,sans-serif",
        "text-valign": "center", "text-halign": "center", "text-wrap": "wrap", "text-max-width": 96,
        "width": 48, "height": 48, "border-width": 1.5, "border-color": "#0b0f14",
        "text-outline-width": 2, "text-outline-color": "#0b0f14"}},
    {"selector": 'node[kind="goal"]', "style": {
        "shape": "round-hexagon", "background-color": "#f2c94c", "color": "#1a1200",
        "text-outline-color": "#f2c94c", "width": 78, "height": 78, "font-size": 12, "font-weight": "bold"}},
    {"selector": 'node[kind="intent"]', "style": {
        "shape": "round-rectangle", "background-color": "#4aa3ff", "width": 66, "height": 40}},
    {"selector": 'node[kind="fact"]', "style": {
        "shape": "ellipse", "background-color": "#586b7d", "width": 40, "height": 40}},
    {"selector": 'node[kind="asset"]', "style": {
        "shape": "round-rectangle", "background-color": "#1f9e8f", "width": 64, "height": 42}},
    {"selector": 'node[kind="operation"]', "style": {
        "shape": "round-tag", "background-color": "#b48ead", "color": "#160a1a",
        "text-outline-color": "#b48ead", "width": 58, "height": 40}},
    {"selector": 'node[kind="finding"]', "style": {"shape": "diamond", "width": 58, "height": 58}},
    {"selector": 'node[sev="crit"]', "style": {"background-color": "#ff5c6c", "text-outline-color": "#3a1216"}},
    {"selector": 'node[sev="high"]', "style": {"background-color": "#ff8c42", "text-outline-color": "#3a2410"}},
    {"selector": 'node[sev="med"]', "style": {"background-color": "#f2c94c", "color": "#1a1200", "text-outline-color": "#f2c94c"}},
    {"selector": 'node[sev="low"]', "style": {"background-color": "#8b98a5", "text-outline-color": "#20262d"}},
    {"selector": 'node[sev="unrated"]', "style": {"background-color": "#6e7681"}},
    {"selector": "edge", "style": {
        "label": "data(label)", "font-size": 7, "color": "#8b98a5", "text-rotation": "autorotate",
        "text-outline-width": 2, "text-outline-color": "#0b0f14",
        "width": 1, "line-color": "#2c3742", "target-arrow-color": "#2c3742",
        "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier"}},
    {"selector": "edge.op-edge", "style": {
        "line-color": "#5a3d63", "target-arrow-color": "#5a3d63", "line-style": "dashed"}},
    {"selector": "edge.path", "style": {
        "width": 3, "line-color": "#4aa3ff", "target-arrow-color": "#4aa3ff", "color": "#cdd9e5", "z-index": 20}},
    {"selector": "node.path", "style": {"border-width": 2.5, "border-color": "#4aa3ff"}},
    {"selector": ".faded", "style": {"opacity": 0.12, "text-opacity": 0.05}},
    {"selector": "node.sel", "style": {"border-width": 3, "border-color": "#fff"}},
])

_FCOSE = json.dumps({"name": "fcose", "quality": "proof", "animate": True, "animationDuration": 600,
                     "nodeSeparation": 90, "idealEdgeLength": 105, "nodeRepulsion": 8500,
                     "padding": 30, "randomize": True})

# Left-to-right hierarchical "exploration chain" — the dsh-pentest flow.png look
# (goal → intent → fact → finding reads as a pipeline, not a force blob).
_DAGRE = json.dumps({"name": "dagre", "rankDir": "LR", "nodeSep": 26, "rankSep": 70,
                     "edgeSep": 12, "animate": True, "animationDuration": 500,
                     "padding": 30, "fit": True})

_LEGEND_KINDS = [
    ("goal", "Goal", ""), ("intent", "Intent", ""), ("fact", "Fact", "round"),
    ("asset", "Asset", ""), ("finding", "Finding", ""), ("operation", "Operation", ""),
]
_LEGEND_COLORS = {"goal": "#f2c94c", "intent": "#4aa3ff", "fact": "#586b7d",
                  "asset": "#1f9e8f", "finding": "#ff5c6c", "operation": "#b48ead"}


def _legend_html() -> str:
    rows = []
    for kind, label, shp in _LEGEND_KINDS:
        rows.append(
            f'<div class="row" data-kind="{kind}">'
            f'<span class="dot {shp}" style="background:{_LEGEND_COLORS[kind]}"></span>{label}</div>')
    return ('<div class="gx legend"><h4>Node types</h4>' + "".join(rows)
            + '<div class="meta" style="margin-top:6px">click to filter</div></div>')


def _script(elements: list[dict]) -> str:
    # Embed graph data as JSON assigned to a var (labels are canvas text; the
    # detail panel uses textContent) — guard the </script> break-out sequence.
    data = json.dumps({"elements": elements}).replace("</", "<\\/")
    return f"""
<script>
(function(){{
  var GRAPH = {data};
  var STYLE = {_STYLE};
  var LAYOUT_FORCE = {_FCOSE};
  var LAYOUT_FLOW = {_DAGRE};
  var cy=null, hidden={{}}, currentLayout="flow";

  function layoutFor(name){{
    if(name==="force") return window.cytoscapeFcose ? LAYOUT_FORCE : {{name:"cose",animate:false}};
    if(window.cytoscapeDagre) return LAYOUT_FLOW;           // preferred LR flow
    if(window.cytoscapeFcose) return LAYOUT_FORCE;          // fallback: force
    return {{name:"breadthfirst",directed:true,spacingFactor:1.15,animate:true}};  // built-in
  }}
  function runLayout(name){{
    currentLayout=name;
    if(cy){{ cy.layout(layoutFor(name)).run(); }}
    document.querySelectorAll(".ctl-btn").forEach(function(b){{
      b.classList.toggle("active", b.dataset.layout===name); }});
  }}

  function fieldRows(d){{
    var rows=[];
    function add(k,v){{ if(v!==undefined&&v!==null&&v!=="") rows.push([k,v]); }}
    add("Type", d.kind);
    if(d.kind==="goal"){{ add("Target", d.label); add("Objective", d.objective); add("Authorization", d.authorization); }}
    else if(d.kind==="intent"){{ add("Intent", d.title); add("Status", d.status); }}
    else if(d.kind==="fact"){{ add("Observation", d.text); }}
    else if(d.kind==="asset"){{ add("Name", d.name); add("Asset type", d.atype); }}
    else if(d.kind==="finding"){{ add("Finding", d.finding_id); add("Title", d.title); add("Severity", d.severity);
        add("Proven by", d.proven_by); add("Affects", d.affects);
        if(d.steps&&d.steps.length) add("Steps", d.steps.map(function(s,i){{return (i+1)+". "+s;}}).join("\\n")); }}
    else if(d.kind==="operation"){{ add("Technique", (d.technique||"")+(d.technique_name?" — "+d.technique_name:""));
        add("Tactic", d.tactic); add("Tool", d.tool); add("Command", d.command); add("Target", d.target);
        add("Time", d.ts); if(d.rc!==null&&d.rc!==undefined) add("Return code", d.rc);
        if(d.loot&&d.loot.length) add("Loot", d.loot.join("\\n")); }}
    return rows;
  }}
  function showDetail(d){{
    var box=document.getElementById("detail");
    box.innerHTML="";
    var close=document.createElement("span"); close.className="close"; close.textContent="✕";
    close.onclick=function(){{ box.classList.remove("show"); if(cy) cy.$(".sel").removeClass("sel"); }};
    box.appendChild(close);
    var h=document.createElement("h4"); h.textContent=(d.label||d.id||d.kind); box.appendChild(h);
    fieldRows(d).forEach(function(r){{
      var k=document.createElement("div"); k.className="k"; k.textContent=r[0]; box.appendChild(k);
      var v=document.createElement("div"); v.className="v"; v.textContent=String(r[1]); box.appendChild(v);
    }});
    box.classList.add("show");
  }}
  function initGraph(){{
    var host=document.getElementById("cy");
    if(!window.cytoscape){{ host.innerHTML='<div class="cy-fail">Security graph unavailable: cytoscape.js failed to load from jsdelivr (offline?). Retry with network access.</div>'; return; }}
    if(window.cytoscapeFcose){{ try{{ cytoscape.use(window.cytoscapeFcose); }}catch(e){{}} }}
    if(window.cytoscapeDagre){{ try{{ cytoscape.use(window.cytoscapeDagre); }}catch(e){{}} }}
    cy=cytoscape({{ container:host, elements:GRAPH.elements, style:STYLE,
                    layout:layoutFor(currentLayout), wheelSensitivity:0.25 }});
    cy.on("tap","node",function(ev){{ cy.$(".sel").removeClass("sel"); ev.target.addClass("sel"); showDetail(ev.target.data()); }});
    cy.on("tap",function(ev){{ if(ev.target===cy){{ document.getElementById("detail").classList.remove("show"); cy.$(".sel").removeClass("sel"); }} }});
    cy.on("mouseover","node",function(ev){{ var n=ev.target; var keep=n.closedNeighborhood(); cy.elements().not(keep).addClass("faded"); }});
    cy.on("mouseout","node",function(){{ cy.elements().removeClass("faded"); }});
  }}
  function applyFilter(){{
    if(!cy) return;
    cy.batch(function(){{
      cy.nodes().forEach(function(n){{
        var off=hidden[n.data("kind")];
        n.style("display", off?"none":"element");
      }});
    }});
  }}
  function wireLegend(){{
    document.querySelectorAll(".legend .row").forEach(function(row){{
      row.addEventListener("click",function(){{
        var k=row.dataset.kind; hidden[k]=!hidden[k];
        row.classList.toggle("off", !!hidden[k]); applyFilter();
      }});
    }});
  }}
  function show(name){{
    document.querySelectorAll(".tab").forEach(function(t){{ t.classList.toggle("active", t.dataset.tab===name); }});
    document.querySelectorAll(".panel").forEach(function(p){{ p.classList.toggle("active", p.id==="panel-"+name); }});
    if(name==="graph"&&cy){{ setTimeout(function(){{ cy.resize(); cy.fit(null,40); }},30); }}
  }}
  document.addEventListener("DOMContentLoaded",function(){{
    document.querySelectorAll(".tab").forEach(function(t){{ t.addEventListener("click",function(){{ show(t.dataset.tab); }}); }});
    document.querySelectorAll(".ctl-btn").forEach(function(b){{ b.addEventListener("click",function(){{ runLayout(b.dataset.layout); }}); }});
    wireLegend();
    initGraph();  // graph is the default-active panel — its container is visible now.
    document.querySelectorAll(".ctl-btn").forEach(function(b){{ b.classList.toggle("active", b.dataset.layout===currentLayout); }});
  }});
}})();
</script>
"""


_TABS = (("graph", "Security Graph"), ("operations", "Operations"),
         ("findings", "Findings"), ("assets", "Assets"), ("report", "Report"))

_CDN = (
    '<script src="https://cdn.jsdelivr.net/npm/cytoscape@3/dist/cytoscape.min.js"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/layout-base/layout-base.js"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/cose-base/cose-base.js"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/cytoscape-fcose@2/cytoscape-fcose.js"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></script>\n'
    '<script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2/cytoscape-dagre.js"></script>\n'
)


def render_engagement_html(domain: str, graph: dict) -> str:
    """A complete, self-contained tabbed engagement page (dark Wiz-style).

    Centerpiece: an interactive cytoscape.js security graph (goal → intent →
    fact → asset → finding + ATT&CK operation nodes from read_oplog). Secondary
    tabs: Operations (oplog + loot timeline), Findings, Report. cytoscape +
    cytoscape-fcose from jsdelivr are the only external resources.
    """
    g = graph.get("goal", {})
    oplog = read_oplog(domain)
    loot = read_loot(domain)
    elements = _build_elements(graph, oplog, loot)

    counts = {
        "intent": len(E._nodes_of(graph, "intent")),
        "fact": len(E._nodes_of(graph, "fact")),
        "finding": len(E._nodes_of(graph, "finding")),
        "asset": len(E._nodes_of(graph, "asset")),
        "operation": len(oplog),
    }

    graph_panel = (
        '<div class="graph-wrap">'
        '<div id="cy"></div>'
        + _legend_html()
        + '<div class="gx detail" id="detail"></div>'
        + '<div class="gx controls">'
          '<button class="ctl-btn" data-layout="flow">Flow</button>'
          '<button class="ctl-btn" data-layout="force">Force</button></div>'
        + '<div class="gx hint">Flow = exploration chain · Force = Wiz graph · '
          'drag to pan · scroll to zoom · click a node for detail</div>'
        + "</div>")
    panels = {
        "graph": graph_panel,
        "operations": _operations_panel(oplog, loot),
        "findings": _findings_panel(graph),
        "assets": _assets_panel(graph),
        "report": markdown_to_html(E.render_report(graph)),
    }
    # Tab labels carry counts (Findings(1) · Assets(3)); None = no count shown.
    tab_counts = {"operations": counts["operation"] or None,
                  "findings": counts["finding"], "assets": counts["asset"]}
    nav_parts = []
    for key, label in _TABS:
        c = tab_counts.get(key)
        cnt = f' <span class="cnt">({c})</span>' if c is not None else ""
        nav_parts.append(
            f'<button class="tab{" active" if key == "graph" else ""}" '
            f'data-tab="{key}">{label}{cnt}</button>')
    nav = "".join(nav_parts)
    body = [f'<h1>{_esc(g.get("target") or domain)}</h1>',
            f'<div class="meta">Objective: {_esc(g.get("objective") or "—")} · '
            f'Authorization: {_esc(g.get("authorization") or "—")}</div>',
            _count_chips(counts),
            f'<div class="tabs">{nav}</div>']
    for key, _label in _TABS:
        active = " active" if key == "graph" else ""
        body.append(f'<div class="panel{active}" id="panel-{key}">\n{panels[key]}\n</div>')

    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc('Engagement — ' + domain)}</title>\n"
        f"<style>{_CSS_BASE}{_TAB_CSS}</style>\n"
        f"{_CDN}"
        f"{_script(elements)}\n"
        '</head>\n<body><div class="report">\n' + "\n".join(body) + "\n</div></body></html>\n"
    )
