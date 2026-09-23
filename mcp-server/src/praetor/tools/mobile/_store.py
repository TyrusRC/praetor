"""Operator-log + loot + artifact glue for the mobile lane.

Device actions bypass Burp, so their evidence is an oplog id (not a Burp
proxy_history_index). Pulled files get loot chain-of-custody. Screenshots land under
artifacts/mobile/.
"""

from __future__ import annotations

from pathlib import Path

from praetor.tools.redteam._oplog import record_action, record_loot
from praetor.tools.workspace import ensure_workspace


def artifact_dir(domain: str) -> Path:
    root = Path(ensure_workspace(domain)["root"])
    d = root / "artifacts" / "mobile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_action(domain: str, dev_id: str, command: str, *, description: str = "",
               output: str = "", rc: int | None = None,
               tags: list[str] | None = None) -> str:
    """Append a mobile device-control action to the operator log; return its id."""
    return record_action(
        domain, tool="mobile", command=command, description=description,
        target=dev_id, output=output, returncode=rc,
        tactic="Execution", technique="T1575",  # Native API / on-device exec
        tags=tags,
    )


def log_loot(domain: str, loot_type: str, path: str, source_host: str,
             oplog_id: str = "") -> dict:
    """Record a pulled artifact (file) with chain-of-custody."""
    return record_loot(domain, loot_type, path, source_host=source_host,
                       obtained_via="mobile", oplog_id=oplog_id, is_path=True)
