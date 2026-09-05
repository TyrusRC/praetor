"""Benchmark run + summary: run_xbow_bench, summarize_benchmarks (split)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.notes._helpers import _intel_dir
from praetor.tools.recon._common import _check_tool, _run_cmd

from . import _core
from ._core import _bench_root, _save_run


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_xbow_bench(
        challenge_id: str,
        challenge_path: str = "",
        target_url: str = "",
        timeout: int = 1800,
    ) -> dict:
        """Run an XBOW Validation Benchmark challenge end-to-end + record result.

        Pattern matches run_autopenbench: operator spins docker, fires grow-agent
        at the target, grow-agent writes extracted flag to a known path, this
        tool reads + compares against benchmark.json win_condition.

        Args:
            challenge_id: XBOW challenge id (e.g. 'XBEN-001-24').
            challenge_path: local path to the challenge dir (auto-discovered if empty).
            target_url: live target URL (default 'http://localhost:8080').
            timeout: seconds.
        """
        from pathlib import Path as _P
        if not _core._check_tool("docker"):
            return {"error": "docker not installed", "hint": "Install Docker Engine"}

        if not challenge_path:
            for root in (
                _P.home() / ".praetor" / "benchmarks" / "xbow" / "benchmarks",
                _P.cwd() / "validation-benchmarks" / "benchmarks",
            ):
                candidate = root / challenge_id
                if candidate.exists():
                    challenge_path = str(candidate)
                    break
            if not challenge_path:
                return {"error": "challenge dir not found",
                        "hint": "call xbow_pull_benchmarks() or pass challenge_path"}

        cfg_path = _P(challenge_path) / "benchmark.json"
        if not cfg_path.exists():
            return {"error": f"benchmark.json missing at {cfg_path}"}
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return {"error": f"benchmark.json parse failure: {e}"}

        level = int(cfg.get("level", 0))
        win_cond = cfg.get("win_condition") or cfg.get("flag") or ""
        # XBOW challenges use a randomised FLAG injected at build time —
        # operator should set XBEN_FLAG env or pass the literal as win_condition.
        if win_cond.startswith("FLAG{"):
            expected = win_cond
        else:
            expected = ""

        flag_file = _bench_root() / "xbow" / f"{challenge_id}-flag.txt"
        if not flag_file.exists():
            return {
                "benchmark": "XBOW",
                "challenge_id": challenge_id,
                "level": level,
                "status": "awaiting_grow_agent",
                "target_url": target_url or "http://localhost:8080",
                "message": (
                    f"flag file not yet written. Fire grow-agent with "
                    f"target={target_url or 'http://localhost:8080'}, "
                    f"objective='extract flag and write to {flag_file}', "
                    f"then re-run run_xbow_bench."
                ),
                "flag_path": str(flag_file),
                "expected_present": bool(expected),
            }

        submitted = flag_file.read_text(encoding="utf-8").strip()
        # XBOW scoring: literal flag match only. When the operator did NOT supply
        # the expected flag, a well-formed FLAG{} shape is NOT a pass — it is an
        # unverified submission (passed=None) the operator must confirm. Scoring
        # a shape-match as passed=True would inflate the published leaderboard
        # number, which is exactly the gaming the module docstring refuses.
        well_formed = submitted.startswith("FLAG{") and submitted.endswith("}")
        if expected:
            passed = submitted == expected
            record = {
                "benchmark": "XBOW",
                "challenge_id": challenge_id,
                "level": level,
                "expected": expected if passed else "(redacted)",
                "submitted": submitted if passed else "(submitted, no match)",
                "passed": passed,
                "submitted_at": int(time.time()),
            }
        else:
            passed = None  # no expected flag — cannot score, awaits human verify
            record = {
                "benchmark": "XBOW",
                "challenge_id": challenge_id,
                "level": level,
                "passed": None,
                "unverified": True,
                "well_formed": well_formed,
                "submitted_present": bool(submitted),
                "submitted_at": int(time.time()),
                "note": "no expected flag supplied — human-verify; NOT counted as a pass",
            }
        path = _save_run("xbow", challenge_id, record)
        return {
            "benchmark": "XBOW",
            "challenge_id": challenge_id,
            "level": level,
            "passed": passed,
            "unverified": expected == "",
            "record_path": str(path),
        }

    @mcp.tool()
    async def summarize_benchmarks() -> dict:
        """Summarise all recorded benchmark runs under .burp-intel/_bench/.

        XBOW runs additionally break down by difficulty level (1/2/3) so the
        operator can publish per-tier scores matching the XBOW leaderboard format.
        """
        root = _bench_root()
        if not root.exists():
            return {"benchmarks": [], "total_runs": 0}
        summary: dict[str, dict] = {}
        for bench_dir in root.iterdir():
            if not bench_dir.is_dir():
                continue
            passed = failed = unverified = 0
            by_level: dict[int, dict[str, int]] = {}
            for f in bench_dir.glob("*.json"):
                try:
                    r = json.loads(f.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                pv = r.get("passed")
                if pv is True:
                    passed += 1
                elif pv is False:
                    failed += 1
                elif r.get("unverified") or r.get("submitted_present"):
                    # Submitted but not scored (no expected flag) — count it so
                    # a whole benchmark (e.g. CAIBench) isn't silently invisible.
                    unverified += 1
                level = r.get("level")
                if isinstance(level, int) and level > 0:
                    by_level.setdefault(level, {"passed": 0, "failed": 0})
                    if pv is True:
                        by_level[level]["passed"] += 1
                    elif pv is False:
                        by_level[level]["failed"] += 1
            entry: dict = {"passed": passed, "failed": failed,
                           "unverified": unverified,
                           "total": passed + failed + unverified}
            if by_level:
                entry["by_level"] = {str(k): v for k, v in sorted(by_level.items())}
            summary[bench_dir.name] = entry
        return {"benchmarks": summary,
                "total_runs": sum(s["total"] for s in summary.values())}
