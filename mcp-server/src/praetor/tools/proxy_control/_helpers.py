"""Shared constants + finding-annotation helpers for proxy_control."""

import json

# Headers whose rewriting frequently breaks traffic or leaks auth. Flag before applying.
_DANGEROUS_HEADER_PATTERNS = (
    "host:",               # breaks TLS SNI / vhost routing
    "authorization:",      # auth-leak risk if replaced globally
    "cookie:",             # session leak across targets
    "content-length:",     # mismatches body length → smuggling/500s
    "transfer-encoding:",  # request smuggling risk
)


def _lookup_finding_id(finding_id: str) -> tuple[bool, str]:
    """Resolve a finding ID across every .burp-intel domain.

    Returns (exists, "<domain> <title>"). Never raises — a missing or corrupt
    store just means "not found", and the caller refuses the annotation.
    """
    try:
        from praetor.tools.notes._helpers import _intel_dir
        root = _intel_dir()
    except Exception:
        return False, ""
    if not root.exists():
        return False, ""
    for d in sorted(root.iterdir()):
        path = d / "findings.json"
        if not path.is_file():
            continue
        try:
            store = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for f in store.get("findings", []) or []:
            if f.get("id") == finding_id:
                return True, f"{d.name} {f.get('title', '')}".strip()
    return False, ""


def _record_annotation_on_finding(finding_id: str, verified: dict) -> None:
    """Append a Burp-confirmed annotation to the finding record. Best-effort.

    Stores the read-back (what Burp actually holds), never the requested text.
    Re-annotating the same index replaces the entry rather than stacking, so
    the list always matches the live history.
    """
    try:
        from praetor.tools.notes._helpers import _intel_dir
        root = _intel_dir()
        if not root.exists():
            return
        for d in sorted(root.iterdir()):
            path = d / "findings.json"
            if not path.is_file():
                continue
            try:
                store = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for f in store.get("findings", []) or []:
                if f.get("id") != finding_id:
                    continue
                tags = [
                    a for a in (f.get("annotations") or [])
                    if isinstance(a, dict) and a.get("index") != verified.get("index")
                ]
                tags.append(verified)
                f["annotations"] = tags
                path.write_text(json.dumps(store, indent=2), encoding="utf-8")
                return
    except Exception:
        pass  # annotation bookkeeping never blocks the annotate call
