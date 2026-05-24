"""CI/CD pipeline audit wrappers — poutine, octoscan.

Both OSS. Detect GitHub Actions injection, pwn-request, untrusted-checkout,
secret leakage, third-party-action pinning, ARTIFACT poisoning patterns.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_poutine(
        target: str,
        mode: str = "local",
        platform: str = "github",
        timeout: int = 600,
    ) -> str:
        """Run poutine CI/CD security analyzer (Boost Security).

        Args:
            target: local repo path | org/repo (GH) | namespace/project (GL).
            mode: local | analyze_repo | analyze_org.
            platform: github | gitlab.
            timeout: seconds.
        """
        if not _check_tool("poutine"):
            return _hint("poutine",
                         "brew install boostsecurityio/tap/poutine  |  "
                         "https://github.com/boostsecurityio/poutine/releases")
        if mode == "local":
            cmd = ["poutine", "analyze_local", "--path", target,
                   "--format", "json"]
        elif mode == "analyze_repo":
            cmd = ["poutine", "analyze_repo", target, "--format", "json",
                   "--scm", platform]
        elif mode == "analyze_org":
            cmd = ["poutine", "analyze_org", target, "--format", "json",
                   "--scm", platform]
        else:
            return f"Error: mode must be local|analyze_repo|analyze_org (got {mode!r})."
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = data.get("findings") or data.get("Findings") or []
        lines = [f"poutine [{mode}/{platform}]: {len(findings)} findings on {target}"]
        for f in findings[:50]:
            rid = f.get("rule_id") or f.get("RuleID") or "?"
            sev = f.get("level") or f.get("Severity") or "?"
            path = f.get("meta", {}).get("path") or f.get("Path") or "?"
            lines.append(f"  [{sev:<8}] {rid}  {path}")
        if rc != 0 and not findings:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_octoscan(repo_path: str, timeout: int = 300) -> str:
        """Run octoscan GitHub Actions static analyzer (Synacktiv).

        Args:
            repo_path: local clone path (looks for .github/workflows/).
            timeout: seconds.
        """
        if not _check_tool("octoscan"):
            return _hint("octoscan",
                         "go install github.com/synacktiv/octoscan@latest  |  "
                         "https://github.com/synacktiv/octoscan")
        out, err, rc = await _run_cmd(
            ["octoscan", "scan", repo_path, "--json"],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError:
            data = []
        if not isinstance(data, list):
            data = data.get("findings") or []
        lines = [f"octoscan: {len(data)} findings in {repo_path}"]
        for f in data[:50]:
            sev = f.get("severity") or "?"
            rule = f.get("rule") or f.get("rule_id") or "?"
            file = f.get("file") or "?"
            msg = (f.get("message") or "")[:80]
            lines.append(f"  [{sev:<8}] {rule}  {file}  -- {msg}")
        if rc != 0 and not data:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)
