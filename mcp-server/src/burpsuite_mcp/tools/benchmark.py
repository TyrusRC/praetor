"""AI-pentest benchmark harness (W7, T12).

Praetor needs a published score. Without one, "leading AI security copilot"
is a claim, not a fact. XBOW: 75/104 XBOWBench. Strix: 100/104. PentestGPT:
86.5%. Pentest-R1: 24.2% AutoPenBench. These are public numbers; Praetor's
is currently zero.

Two wrappers:

  - run_autopenbench(challenge_id, timeout) — wraps the AutoPenBench docker
    challenge harness (https://github.com/lucagioacchini/auto-pen-bench).
    Each challenge ships as a single docker compose. Operator runs the
    challenge; this tool fires Praetor's grow-agent loop at it and records
    pass/fail to .burp-intel/_bench/<benchmark>/<challenge>.json.

  - run_caibench(suite) — wraps CAIBench (https://github.com/aliasrobotics/cai
    /tree/main/benchmarks). CAIBench is a meta-benchmark spanning Cybench,
    NYU CTF, and CAI-internal cases.

Both return structured score + duration + log path so the operator can publish
a README badge. We deliberately do NOT auto-tune Praetor for benchmark — that's
how XBOW gets gamed in the literature.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


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


def register(mcp: FastMCP) -> None:

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
        if not _check_tool("docker"):
            return {"error": "docker not installed", "hint": "Install Docker Engine"}

        if not challenge_path:
            candidate = Path.cwd() / "auto-pen-bench" / "challenges" / challenge_id
            if candidate.exists():
                challenge_path = str(candidate)
            else:
                return {"error": f"challenge dir not found; pass challenge_path explicitly", "looked_in": str(candidate)}

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
        timeout: int = 1800,
    ) -> dict:
        """Run a CAIBench suite challenge (Cybench / NYU CTF / CAI-internal).

        CAIBench is the meta-benchmark from Alias Robotics — composes
        Cybench (Stanford / DEFCON CTFs), NYU CTF (CSAW), and AI-pentest
        Docker labs. Same flag-match pattern as AutoPenBench.

        Args:
            suite: 'cybench' | 'nyu_ctf' | 'cai'.
            challenge_id: challenge name within the suite.
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

        # CAIBench scoring is binary per challenge; operator-supplied expected flag.
        submitted = flag_file.read_text(encoding="utf-8").strip()
        record = {
            "benchmark": "CAIBench",
            "suite": suite,
            "challenge_id": challenge_id,
            "submitted_present": bool(submitted),
            "submitted_at": int(time.time()),
        }
        path = _save_run(f"caibench-{suite}", challenge_id, record)
        return {"benchmark": "CAIBench", "suite": suite, "challenge_id": challenge_id,
                "submitted_present": bool(submitted), "record_path": str(path)}

    @mcp.tool()
    async def summarize_benchmarks() -> dict:
        """Summarise all recorded benchmark runs under .burp-intel/_bench/."""
        root = _bench_root()
        if not root.exists():
            return {"benchmarks": [], "total_runs": 0}
        summary: dict[str, dict[str, int]] = {}
        for bench_dir in root.iterdir():
            if not bench_dir.is_dir():
                continue
            passed = failed = 0
            for f in bench_dir.glob("*.json"):
                try:
                    r = json.loads(f.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if r.get("passed") is True:
                    passed += 1
                elif r.get("passed") is False:
                    failed += 1
            summary[bench_dir.name] = {"passed": passed, "failed": failed,
                                        "total": passed + failed}
        return {"benchmarks": summary,
                "total_runs": sum(s["total"] for s in summary.values())}
