"""Episodic memory — action→outcome traces so dead-end probes aren't repeated.

Complements coverage.json (which records tested tuples + verdicts) by capturing
the *narrative*: "I ran probe X against Y and got Z" — including dead ends,
non-tuple actions, and methodology lessons. PentAGI/PentesterFlow prior art
(episodic store + selective recall). Persisted as JSONL under the engagement
workspace, credential-redacted before write.

Path: .burp-intel/<domain>/episodes.jsonl  (gitignored with the rest of intel).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ._internals import _intel_path


# Redact obvious secrets before anything is persisted (Rule: never write creds
# to disk). Shapes only — bearer tokens, cookies, api keys, passwords, JWTs.
_REDACTORS = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(cookie:\s*)[^\n]+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*)['\"]?[^\s'\"&]{6,}"), r"\1<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b"), "<redacted-jwt>"),
]


def _redact(text: str) -> str:
    out = text or ""
    for pat, repl in _REDACTORS:
        out = pat.sub(repl, out)
    return out


def _episodes_path(domain: str):
    return _intel_path(domain) / "episodes.jsonl"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def record_probe_outcome(
        domain: str,
        action: str,
        target: str,
        outcome: str,
        result: str = "inconclusive",
    ) -> str:
        """Append an action→outcome trace to episodic memory (credential-redacted).

        Call after a probe/test that produced a notable result — especially
        DEAD ENDS, so the same unproductive probe isn't repeated next session.

        Args:
            domain: Target domain.
            action: What was tried (e.g. "auto_probe ssti on /render?q").
            target: Endpoint/param acted on.
            outcome: Short result (e.g. "no reflection", "WAF 403", "confirmed").
            result: one of confirmed | suspected | dead_end | inconclusive.
        """
        if not domain or not action:
            return "Error: domain and action required."
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": _redact(action)[:400],
            "target": _redact(target)[:300],
            "outcome": _redact(outcome)[:400],
            "result": (result or "inconclusive").strip().lower(),
        }
        path = _episodes_path(domain)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return f"episode recorded for {domain}: [{entry['result']}] {entry['action']}"

    @mcp.tool()
    async def recall_probe_outcomes(
        domain: str,
        query: str = "",
        result_filter: str = "",
        limit: int = 20,
    ) -> str:
        """Recall past action→outcome traces — selective, not a full dump.

        Use before re-testing to avoid repeating dead ends. Filters by substring
        match on action/target/outcome and optionally by result state.

        Args:
            domain: Target domain.
            query: Substring to match (empty = most recent).
            result_filter: Optional result state (dead_end / confirmed / suspected).
            limit: Max traces to return (newest first).
        """
        path = _episodes_path(domain)
        if not path.exists():
            return f"No episodic memory for {domain} yet."
        q = query.strip().lower()
        rf = result_filter.strip().lower()
        rows = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rf and e.get("result") != rf:
                    continue
                if q and q not in json.dumps(e).lower():
                    continue
                rows.append(e)
        except OSError as exc:
            return f"episodes.jsonl unreadable: {exc}"
        if not rows:
            return f"No matching episodes for {domain} (query='{query}', result='{result_filter}')."
        rows = rows[-limit:][::-1]
        lines = [f"Episodic recall for {domain} ({len(rows)} of {len(rows)} shown):", ""]
        for e in rows:
            lines.append(f"  [{e.get('result','?')}] {e.get('action','')}")
            lines.append(f"      target={e.get('target','')}  → {e.get('outcome','')}")
        return "\n".join(lines)
