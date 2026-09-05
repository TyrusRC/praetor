"""Benchmark runners: autopenbench, caibench, xbow pull (split from benchmark.py)."""

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
    async def run_autopenbench(
        challenge_id: str,
        challenge_path: str = "",
        timeout: int = 1800,
    ) -> dict:
        """Run an AutoPenBench challenge end-to-end + record pass/fail.

        AutoPenBench (Gioacchini et al., 2024) ships 33 docker challenges
        graded by exact-flag match. This tool:
          1. Spins up the challenge docker (operator must `docker compose up`).
          2. Operator fires grow-agent at the challenge target.
          3. Tool reads grow-agent's submitted flag from .burp-intel/_bench/
             <challenge_id>/flag.txt and compares to challenge expected.
          4. Records pass/fail + duration + Praetor tool calls.

        Args:
            challenge_id: AutoPenBench challenge id (e.g. 'in-vitro-rce-1').
            challenge_path: local path to the unpacked challenge dir (auto-discovered if empty).
            timeout: seconds.
        """
        if not _core._check_tool("docker"):
            return {"error": "docker not installed", "hint": "Install Docker Engine"}

        if not challenge_path:
            candidate = Path.cwd() / "auto-pen-bench" / "challenges" / challenge_id
            if candidate.exists():
                challenge_path = str(candidate)
            else:
                return {"error": "challenge dir not found; pass challenge_path explicitly", "looked_in": str(candidate)}

        flag_file = _bench_root() / "autopenbench" / f"{challenge_id}-flag.txt"
        expected_file = Path(challenge_path) / ".flag"
        expected = expected_file.read_text(encoding="utf-8").strip() if expected_file.exists() else ""

        if not flag_file.exists():
            return {
                "challenge_id": challenge_id,
                "status": "awaiting_grow_agent",
                "message": (
                    f"flag file not yet written. Fire `grow-agent` with target=<challenge container>, "
                    f"objective='extract flag and write to {flag_file}', then re-run run_autopenbench."
                ),
                "flag_path": str(flag_file),
                "expected_present": bool(expected),
            }

        submitted = flag_file.read_text(encoding="utf-8").strip()
        passed = bool(expected) and submitted == expected
        record = {
            "benchmark": "AutoPenBench",
            "challenge_id": challenge_id,
            "expected": expected if passed else "(redacted)",
            "submitted": submitted if passed else "(submitted, no match)",
            "passed": passed,
            "submitted_at": int(time.time()),
        }
        path = _save_run("autopenbench", challenge_id, record)
        return {"benchmark": "AutoPenBench", "challenge_id": challenge_id, "passed": passed,
                "record_path": str(path)}

    @mcp.tool()
    async def run_caibench(
        suite: str = "cybench",
        challenge_id: str = "",
        expected_flag: str = "",
        timeout: int = 1800,
    ) -> dict:
        """Run a CAIBench suite challenge (Cybench / NYU CTF / CAI-internal).

        CAIBench is the meta-benchmark from Alias Robotics — composes
        Cybench (Stanford / DEFCON CTFs), NYU CTF (CSAW), and AI-pentest
        Docker labs. Same flag-match pattern as AutoPenBench.

        Args:
            suite: 'cybench' | 'nyu_ctf' | 'cai'.
            challenge_id: challenge name within the suite.
            expected_flag: the challenge's real flag. When supplied the run is
                scored (passed True/False); when omitted the run records as
                unverified (passed=None) for the operator to confirm — it is
                NEVER counted as a pass on shape alone.
            timeout: seconds.
        """
        valid = {"cybench", "nyu_ctf", "cai"}
        if suite not in valid:
            return {"error": f"invalid suite {suite!r}; choose one of {sorted(valid)}"}
        if not challenge_id:
            return {"error": "challenge_id required"}

        flag_file = _bench_root() / "caibench" / suite / f"{challenge_id}-flag.txt"
        if not flag_file.exists():
            return {
                "benchmark": "CAIBench",
                "suite": suite,
                "challenge_id": challenge_id,
                "status": "awaiting_grow_agent",
                "message": (
                    f"flag file not yet written. Fire `grow-agent` with the challenge target and have it write "
                    f"the extracted flag to {flag_file}, then re-run run_caibench."
                ),
                "flag_path": str(flag_file),
            }

        # CAIBench scoring is binary per challenge. Score only when the operator
        # supplied the expected flag; otherwise record unverified (passed=None)
        # so the run is visible but never inflates the pass tally.
        submitted = flag_file.read_text(encoding="utf-8").strip()
        expected = expected_flag.strip()
        passed = (submitted == expected) if expected else None
        record = {
            "benchmark": "CAIBench",
            "suite": suite,
            "challenge_id": challenge_id,
            "passed": passed,
            "unverified": expected == "",
            "expected": expected if passed else ("(redacted)" if expected else ""),
            "submitted": (
                submitted if passed
                else "(submitted, no match)" if expected
                else "(submitted, unverified)"
            ),
            "submitted_present": bool(submitted),
            "submitted_at": int(time.time()),
        }
        path = _save_run(f"caibench-{suite}", challenge_id, record)
        return {"benchmark": "CAIBench", "suite": suite, "challenge_id": challenge_id,
                "passed": passed, "unverified": expected == "",
                "submitted_present": bool(submitted), "record_path": str(path)}

    @mcp.tool()
    async def xbow_pull_benchmarks(
        target_dir: str = "",
    ) -> dict:
        """Clone the XBOW Validation Benchmarks repo (Apache-2.0, 104 challenges).

        Repo: https://github.com/xbow-engineering/validation-benchmarks
        Default target_dir: ~/.praetor/benchmarks/xbow/

        Each challenge ships as a Docker compose under benchmarks/XBEN-<NNN-NN>/
        with benchmark.json carrying name / description / level (1-3) / tags /
        win_condition (CTF flag format: FLAG{<hex>}).

        Operator must `docker compose up -d` per challenge before run_xbow_bench.

        Args:
            target_dir: where to clone. Empty -> ~/.praetor/benchmarks/xbow.
        """
        from pathlib import Path as _P
        if not _core._check_tool("git"):
            return {"error": "git not installed"}
        dest = _P(target_dir).expanduser() if target_dir else (
            _P.home() / ".praetor" / "benchmarks" / "xbow"
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and (dest / ".git").exists():
            out, err, rc = await _core._run_cmd(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                timeout=120, bypass_proxy=True,
            )
            action = "pulled"
        else:
            out, err, rc = await _core._run_cmd(
                ["git", "clone", "--depth", "1",
                 "https://github.com/xbow-engineering/validation-benchmarks",
                 str(dest)],
                timeout=300, bypass_proxy=True,
            )
            action = "cloned"
        if rc != 0:
            return {"error": f"git {action} failed (rc={rc})", "stderr": err[:400]}
        # Count discovered challenges.
        challenges = sorted(
            p.name for p in dest.glob("benchmarks/XBEN-*")
            if (p / "benchmark.json").exists()
        )
        return {
            "benchmark": "XBOW",
            "action": action,
            "target_dir": str(dest),
            "challenges_discovered": len(challenges),
            "sample_ids": challenges[:5],
        }
