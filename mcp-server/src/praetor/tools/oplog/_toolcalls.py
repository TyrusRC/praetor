"""Universal tool-call ledger — every MCP tool invocation, timed.

The operation ledger (`_store`) records only calls that reach Burp; a tool that
does pure analysis / intel / graph work leaves no trace there. This records EVERY
tool call so the whole harness is replayable, auditable, and inspectable after a
compaction — DeepSeek-Harness's "model-visible means logged" invariant applied to
Praetor's tool layer.

Secret-free by design: an entry is the tool name, ok/error, and timing — never an
argument value or a result body (those can carry payloads, tokens, PII). Written at
the central `instrument_tools` seam, best-effort and fail-open (a ledger failure
must never break a tool call).

Disable with PRAETOR_TOOLLOG=off. Global ledger at .burp-intel/_harness/toolcalls.jsonl.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def enabled() -> bool:
    return os.environ.get("PRAETOR_TOOLLOG", "").strip().lower() not in ("off", "0", "false", "no")


def _ledger_path() -> Path:
    return Path.cwd() / ".burp-intel" / "_harness" / "toolcalls.jsonl"


def make_entry(tool: str, ok: bool, elapsed_ms: float, error: str = "") -> dict:
    """Pure: one ledger line. No argument values / result bodies — secret-free."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "ok": bool(ok),
        "elapsed_ms": round(float(elapsed_ms), 1),
    }
    if error:
        entry["error"] = str(error)[:200]
    return entry


def record(tool: str, ok: bool, elapsed_ms: float, error: str = "") -> None:
    """Best-effort append. Never raises — a logging fault must not break the tool."""
    if not enabled():
        return
    try:
        path = _ledger_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(make_entry(tool, ok, elapsed_ms, error)) + "\n")
    except Exception:
        pass   # fail-open: the ledger is diagnostics, never a gate


def read(limit: int = 50, tool: str = "", errors_only: bool = False) -> list[dict]:
    """Most-recent-first ledger entries, optionally filtered by tool / errors."""
    path = _ledger_path()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if tool and e.get("tool") != tool:
            continue
        if errors_only and e.get("ok", True):
            continue
        out.append(e)
        if len(out) >= max(1, limit):
            break
    return out
