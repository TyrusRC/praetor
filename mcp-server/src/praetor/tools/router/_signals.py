"""Read existing target state into a normalized signal set. Best-effort:
missing/malformed files degrade to fewer signals, never a crash."""

import json
import os


def _load(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def collect_signals(domain: str, base_dir: str = ".burp-intel") -> list[dict]:
    root = os.path.join(base_dir, domain)
    if not os.path.isdir(root):
        return []
    sigs: list[dict] = []

    profile = _load(os.path.join(root, "profile.json")) or {}
    for t in profile.get("tech_stack", []) + profile.get("frameworks", []):
        sigs.append({"type": "tech", "value": str(t), "target": domain,
                     "source": "profile"})
    for ep in profile.get("high_value_endpoints", []):
        sigs.append({"type": "params_present", "value": "", "target": str(ep),
                     "source": "profile"})

    findings = _load(os.path.join(root, "findings.json")) or {}
    flist = findings.get("findings", []) if isinstance(findings, dict) else findings
    for f in flist:
        vt = f.get("vuln_type") if isinstance(f, dict) else None
        if vt:
            sigs.append({"type": "finding", "value": vt,
                         "target": f.get("endpoint", domain), "source": "findings"})

    coverage = _load(os.path.join(root, "coverage.json")) or {}
    for c in coverage.get("tested", []):
        sigs.append({"type": "covered", "value": c.get("vuln_type", ""),
                     "target": c.get("endpoint", ""), "source": "coverage"})

    return sigs


def normalize_signals(raw: list[dict]) -> list[dict]:
    out = []
    for s in raw or []:
        out.append({"type": s.get("type", ""), "value": s.get("value", ""),
                    "target": s.get("target", ""), "source": s.get("source", "caller")})
    return out
