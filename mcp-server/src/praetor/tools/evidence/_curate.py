"""Pure findings-update for evidence curation."""


def apply_curation(findings: dict, finding_id: str, index: int,
                   color: str) -> tuple[dict, str]:
    for f in findings.get("findings", []):
        if f.get("id") == finding_id:
            ev = f.setdefault("evidence", {})
            ev["logger_index"] = index
            ev["annotation_color"] = color
            ev["curated"] = True
            return findings, f"Recorded evidence index {index} ({color}) on {finding_id}."
    return findings, f"Finding {finding_id} not found — nothing curated."
