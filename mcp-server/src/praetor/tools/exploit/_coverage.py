"""Coverage + test-journal recording for confirm_*/escalate_* exploit tools.

auto_probe records coverage via scan/_impl.record_coverage(). The exploit
tools bypass auto_probe, so without this helper the coverage heatmap and
checklist system never learn that a class was tested via a targeted tool.

Call record_exploit_coverage() before returning a CONFIRMED or FAILED verdict.
INCONCLUSIVE and ERROR verdicts do NOT count as coverage (Rule 19a).

Every decisive call also writes a structured entry to test_journal.jsonl —
the single file the operator reads to answer "which tests ran, on what, and
what happened?" (coverage.json answers "was it tested?" but not the result).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def record_exploit_coverage(
    domain: str,
    endpoint: str,
    parameter: str,
    vuln_class: str,
    verdict: str = "",
    tool_name: str = "",
    proxy_index: int = -1,
) -> None:
    """Record coverage + test-journal entry for a confirmed/failed exploit test.

    Best-effort — failure never breaks the tool's response.
    """
    if not domain or not endpoint or not vuln_class:
        return
    try:
        from praetor.tools.intel import _knowledge_version, _intel_path

        base = _intel_path(domain)
        base.mkdir(parents=True, exist_ok=True)
        kv = _knowledge_version()
        ts = datetime.now(timezone.utc).isoformat()

        # --- coverage.json (tested-tuple heatmap) ---
        cov_path = base / "coverage.json"
        cov: dict = {"entries": []}
        if cov_path.exists():
            try:
                cov = json.loads(cov_path.read_text(encoding="utf-8")) or {"entries": []}
            except (OSError, json.JSONDecodeError):
                cov = {"entries": []}
        if "entries" not in cov or not isinstance(cov["entries"], list):
            cov["entries"] = []

        key = (endpoint, parameter or "", vuln_class)
        found = False
        for e in cov["entries"]:
            if (e.get("endpoint"), e.get("parameter"), e.get("category")) == key:
                e["knowledge_version"] = kv
                e["verdict"] = verdict or e.get("verdict", "")
                e["tested_at"] = ts
                found = True
                break
        if not found:
            cov["entries"].append({
                "endpoint": endpoint,
                "parameter": parameter or "",
                "category": vuln_class,
                "knowledge_version": kv,
                "source": "exploit_tool",
                "verdict": verdict,
                "tested_at": ts,
            })
        cov_path.write_text(
            json.dumps(cov, separators=(",", ":")), encoding="utf-8"
        )

        # --- test_journal.jsonl (structured test log) ---
        journal_path = base / "test_journal.jsonl"
        entry = {
            "ts": ts,
            "endpoint": endpoint,
            "parameter": parameter or "",
            "vuln_class": vuln_class,
            "verdict": verdict,
            "tool": tool_name,
            "proxy_index": proxy_index if proxy_index >= 0 else None,
        }
        with journal_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    except Exception:
        pass
