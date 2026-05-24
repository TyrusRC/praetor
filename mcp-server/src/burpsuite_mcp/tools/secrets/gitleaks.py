"""gitleaks wrapper — secret detection over git history / local paths.

https://github.com/gitleaks/gitleaks — MIT, ~150 built-in detectors.

Output normalized to a Praetor finding-shape list. Operator pipes findings
into save_finding individually (or via a batch helper in a future wave).
"""

from __future__ import annotations

import json
import shlex
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _summarize(findings: list[dict]) -> str:
    if not findings:
        return "gitleaks: 0 findings (clean)."

    by_rule: dict[str, int] = {}
    for f in findings:
        rid = (f.get("RuleID") or f.get("rule_id") or "?")
        by_rule[rid] = by_rule.get(rid, 0) + 1

    lines = [f"gitleaks: {len(findings)} findings"]
    for rid, count in sorted(by_rule.items(), key=lambda kv: -kv[1])[:25]:
        lines.append(f"  {count}x {rid}")
    lines.append("")
    sample = findings[:5]
    lines.append("Sample (first 5):")
    for f in sample:
        rid = f.get("RuleID") or f.get("rule_id") or "?"
        path = f.get("File") or f.get("file") or "?"
        line = f.get("StartLine") or f.get("line") or 0
        match = (f.get("Match") or f.get("match") or "")[:80]
        lines.append(f"  [{rid}] {path}:{line}  {match!r}")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_gitleaks(
        target: str,
        mode: str = "filesystem",
        timeout: int = 300,
    ) -> str:
        """Run gitleaks against a local path or git repository.

        Args:
            target: Local filesystem path, OR a remote git URL (https://…/repo.git)
            mode:
                'filesystem' = scan files at <target> path
                'git'        = scan git history at <target> path
                'clone'      = git-clone <target> URL then scan history
            timeout: Max seconds (default 300)
        """
        if not _check_tool("gitleaks"):
            return (
                "Error: gitleaks not installed.\n"
                "Install: brew install gitleaks  |  "
                "https://github.com/gitleaks/gitleaks/releases"
            )

        mode = mode.lower().strip()
        if mode not in {"filesystem", "git", "clone"}:
            return f"Error: mode must be filesystem | git | clone (got {mode!r})"

        cleanup_dir: tempfile.TemporaryDirectory | None = None
        scan_path = target
        scan_mode = mode

        try:
            if mode == "clone":
                if not target.startswith(("http://", "https://", "git@")):
                    return "Error: clone mode requires git URL"
                cleanup_dir = tempfile.TemporaryDirectory(prefix="praetor-gitleaks-")
                clone_dir = Path(cleanup_dir.name) / "repo"
                rc_clone = await _run_cmd(
                    ["git", "clone", "--depth", "200", target, str(clone_dir)],
                    timeout=timeout,
                    bypass_proxy=True,
                )
                if rc_clone[2] != 0:
                    return f"git clone failed: {rc_clone[1][:300]}"
                scan_path = str(clone_dir)
                scan_mode = "git"

            if not Path(scan_path).exists():
                return f"Error: scan path not found: {scan_path}"

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                report_path = tf.name

            cmd = [
                "gitleaks",
                "detect" if scan_mode == "git" else "dir",
                "--source", scan_path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner",
                "--exit-code", "0",
            ]
            stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            findings: list[dict] = []
            try:
                report_text = Path(report_path).read_text(encoding="utf-8")
                if report_text.strip():
                    findings = json.loads(report_text)
                    if isinstance(findings, dict):
                        findings = [findings]
            except (OSError, json.JSONDecodeError):
                pass
            finally:
                try:
                    Path(report_path).unlink()
                except OSError:
                    pass

            summary = _summarize(findings or [])
            if rc != 0 and not findings:
                summary += f"\n[gitleaks-rc={rc}]\n{stderr[:500]}"
            return f"# gitleaks scan ({scan_mode}) — {shlex.quote(scan_path)}\n\n{summary}"
        finally:
            if cleanup_dir is not None:
                cleanup_dir.cleanup()
