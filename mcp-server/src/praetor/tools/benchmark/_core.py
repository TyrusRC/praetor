"""benchmark harness shared helpers + tool-availability check (extracted)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.notes._helpers import _intel_dir
from praetor.tools.recon._common import _check_tool, _run_cmd

def _bench_root() -> Path:
    d = _intel_dir() / "_bench"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_run(bench: str, challenge: str, record: dict) -> Path:
    out_dir = _bench_root() / bench
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{challenge}-{int(time.time())}.json"
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return path
