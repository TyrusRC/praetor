"""Evidence-key filter + PoC/repro formatters for report rendering."""


# Evidence keys that only mean something inside this operator's Burp session.
# A client or triager cannot resolve them, and citing them reads as a tool dump
# rather than a finding. Kept out of the delivered report; still in findings.json.
_INTERNAL_EVIDENCE_KEYS = {
    "logger_index", "proxy_history_index", "proxy_index", "history_index",
    "repeater_tab", "repeater_tab_id", "burp_id", "organizer_index",
    "session_name", "scan_id", "task_id", "baseline_index", "annotation_index",
}

# Substrings that mark a value as an internal artifact path or tool-run
# reference rather than evidence about the target.
_INTERNAL_VALUE_MARKERS = (
    ".burp-intel/", "material/tool-output", "testcases/", "/scratchpad/",
    "findings.json", "coverage.json", "checkpoint.json",
)


def _is_internal_evidence(key: str, value: object) -> bool:
    """True when an evidence entry is a Burp/workspace bookkeeping reference.

    The name list alone was not enough. Operators label evidence with keys the
    list cannot enumerate ahead of time — `true_branch_index`, `baseline_index`,
    `quote_break_index` — and each one is still a pointer into this operator's
    Burp session that the reader cannot resolve. Any `*_index` / `*_indices`
    key is bookkeeping regardless of its prefix.
    """
    k = str(key).lower()
    if k in _INTERNAL_EVIDENCE_KEYS or k.endswith(("_index", "_indices")):
        return True
    s = str(value)
    return any(m in s for m in _INTERNAL_VALUE_MARKERS)


def extract_screenshots(evidence: object) -> list[dict]:
    """Pull screenshot references out of a finding's evidence.

    Accepts the canonical `evidence.screenshots = [{file, note}]` plus a legacy
    scalar `evidence.screenshot` (a bare path/filename). Returns a normalised
    list of `{file, note}`. Screenshots are deliverable evidence, rendered
    separately from the generic evidence rows so the internal-path filter never
    strips them.
    """
    if not isinstance(evidence, dict):
        return []
    out: list[dict] = []
    raw = evidence.get("screenshots")
    if isinstance(raw, list):
        for s in raw:
            if isinstance(s, dict) and s.get("file"):
                out.append({"file": str(s["file"]), "note": str(s.get("note", "")),
                            "step": str(s.get("step", ""))})
            elif isinstance(s, str) and s.strip():
                out.append({"file": s.strip(), "note": "", "step": ""})
    legacy = evidence.get("screenshot")
    if isinstance(legacy, str) and legacy.strip():
        out.append({"file": legacy.strip(), "note": "", "step": ""})
    # Order by PoC step (shots with a step first, natural-sorted on the leading
    # number so 10-cleanup follows 2-attack; then the rest in capture order) so
    # the report reads baseline -> attack -> result.
    import re as _re

    def _key(i_s):
        i, s = i_s
        step = s.get("step", "")
        if not step:
            return (1, 0, "", i)
        m = _re.match(r"(\d+)", step)
        return (0, int(m.group(1)) if m else 0, step, i)
    return [s for _, s in sorted(enumerate(out), key=_key)]


def format_poc_request(poc: dict | str | None) -> str:
    """Render a poc_request dict (or string) as an http code block."""
    if isinstance(poc, dict):
        method = poc.get("method", "GET")
        path = poc.get("path", "/")
        host = poc.get("host", "")
        out = ["```http", f"{method} {path} HTTP/1.1"]
        if host:
            out.append(f"Host: {host}")
        for k, v in poc.get("headers", {}).items():
            out.append(f"{k}: {v}")
        body = poc.get("body", "")
        if body:
            out.append("")
            out.append(str(body))
        out.append("```")
        return "\n".join(out)
    if isinstance(poc, str) and poc.strip():
        return f"```\n{poc[:1500]}\n```"
    return ""


def format_repro_steps(steps: list | str | None) -> str:
    """Render reproduction steps. Accepts list[str] | list[dict] | str."""
    if isinstance(steps, list):
        out = []
        for i, s in enumerate(steps, 1):
            if isinstance(s, dict):
                desc = s.get("step") or s.get("description") or str(s)
                expected = s.get("expected", "")
                out.append(f"{i}. {desc}")
                if expected:
                    out.append(f"   - Expected: {expected}")
            else:
                out.append(f"{i}. {s}")
        return "\n".join(out)
    if isinstance(steps, str) and steps.strip():
        return steps
    return ""
