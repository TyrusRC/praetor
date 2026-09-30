"""Attack-path map + next-steps section for the report.

Turns `plan_attack_paths` into the part a pentester/red-teamer reads to know
WHERE they are and WHAT to do next: a Mermaid graph of confirmed findings
escalating to high-value objectives (RCE / cloud creds / ATO / mass-PII), and a
"Next steps" list — objectives that are ONE capability away, naming the vuln
class that unlocks each (the next proof to obtain). Each reachable objective also
carries its earliest severing control, so the same section doubles as remediation.

Pure markdown (a ```mermaid fence + lists); the HTML exporter renders the fence
with mermaid.js.
"""

from __future__ import annotations

import re

from praetor.tools.advisor.attack_path import plan_attack_paths_impl


def _san(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", str(s)) or "n"


def _mermaid(data: dict) -> list[str]:
    out = ["```mermaid", "flowchart LR"]
    seen: set[str] = set()

    def node(nid: str, label: str, cls: str = "") -> None:
        if nid not in seen:
            # Strip chars that break a quoted mermaid label (its own brackets, #).
            lbl = re.sub(r'["\[\]{}()#|]', " ", str(label))[:48].strip()
            out.append(f'  {nid}["{lbl}"]' + (f":::{cls}" if cls else ""))
            seen.add(nid)

    for ch in data.get("kill_chains", []):
        seeds = [f"F_{_san(sf.split()[0])}" for sf in ch.get("seed_findings", [])]
        for sf, nid in zip(ch.get("seed_findings", []), seeds):
            node(nid, f"🔎 {sf}", "finding")
        prev = seeds
        steps = ch.get("steps", [])
        for i, step in enumerate(steps):
            cap = step.get("capability", "")
            is_obj = cap == ch.get("objective_cap")
            nid = ("O_" if is_obj else "C_") + _san(cap)
            node(nid, ("🏁 " + ch["objective"]) if is_obj else cap.replace("_", " "),
                 "objective" if is_obj else "")
            label = step.get("attack_ck", "")
            for src in prev:
                out.append(f"  {src} -->|{label}| {nid}" if label else f"  {src} --> {nid}")
            prev = [nid]

    # Near-miss objectives: one capability away — dashed "todo" node with the class.
    for nm in data.get("near_misses", []):
        cls = "/".join(nm.get("next_proof_needed", [])[:2])
        # Include the missing capability in the id — two near-misses for the same
        # objective (different missing caps) must not collide on node id.
        nid = "N_" + _san(nm.get("objective", "")) + "_" + _san(cls)
        node(nid, f"⚠ {nm['objective']} — get {cls}", "todo")

    out += [
        "  classDef finding fill:#e8f0ff,stroke:#4472c4;",
        "  classDef objective fill:#ffe0e0,stroke:#cc3333,font-weight:bold;",
        "  classDef todo fill:#fff6d6,stroke:#d9a300,stroke-dasharray:4 3;",
        "```",
    ]
    return out


async def build_attack_map_section(domain: str) -> str:
    """Markdown 'Attack Path Map & Next Steps' section, or '' when there's nothing
    to map (no findings escalate yet)."""
    data = await plan_attack_paths_impl(domain)
    if not isinstance(data, dict) or data.get("error"):
        return ""
    chains = data.get("kill_chains", [])
    near = data.get("near_misses", [])
    if not chains and not near:
        return ""

    lines = [
        "## Attack Path Map & Next Steps",
        "",
        "How the confirmed findings chain to real impact, and the single next "
        "proof that unlocks each objective still out of reach.",
        "",
    ]
    lines += _mermaid(data)

    if chains:
        lines += ["", "### Reachable objectives", ""]
        for ch in chains:
            seeds = ", ".join(ch.get("seed_findings", [])) or "confirmed findings"
            ctrl = ch.get("earliest_control", "")
            lines.append(
                f"- **{ch['objective']}** ({ch.get('severity','')}, score "
                f"{ch.get('score','')}) — via {seeds}."
                + (f" _Severed by:_ {ctrl}" if ctrl else "")
            )

    if near:
        lines += ["", "### Next steps — one move from impact", ""]
        for nm in near:
            classes = " / ".join(f"`{c}`" for c in nm.get("next_proof_needed", []))
            lines.append(
                f"- **{nm['objective']}** is one capability away — missing "
                f"*{nm['missing_capability']}*; obtain it via {classes}. "
                f"({nm.get('would_complete','')})"
            )

    lines.append("")
    return "\n".join(lines)
