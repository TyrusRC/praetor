"""Source-aware vulnerability hunting wrappers (W7, T11).

When source is available (white-box / grey-box engagement), LLM-chain SAST
catches what regex-only rule engines miss. Two OSS wrappers exposed:

  - run_xvulnhuntr  : CompassSecurity/xvulnhuntr — Python/Java/C# AST chain
                      tracing. Used when source language is typed.
  - run_vulnhuntr   : protectai/vulnhuntr — Python-only original. Used when
                      target is Python-only or as a baseline cross-check.

Both produce findings with `file:line:sink` chains we project into
save_finding.evidence.source_chain — closes the white-box gap surfaced in
W7 research (Praetor had no source-aware probe pipeline).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


_XVULNHUNTR_HINT = (
    "Install xvulnhuntr (Compass Security fork — Python+C#+Java AST adapter):\n"
    "  pipx install git+https://github.com/CompassSecurity/xvulnhuntr.git\n"
    "Requires ANTHROPIC_API_KEY or local LLM endpoint per its README."
)

_VULNHUNTR_HINT = (
    "Install vulnhuntr (Protect AI — Python-only LLM SAST):\n"
    "  pipx install vulnhuntr\n"
    "Requires ANTHROPIC_API_KEY per its README."
)


def _normalise_findings(raw: dict | list) -> list[dict]:
    """Both tools emit slightly different JSON shapes. Normalise into a flat list."""
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("findings") or raw.get("results") or raw.get("vulnerabilities") or []
    else:
        return []
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        chain = item.get("source_chain") or item.get("call_chain") or item.get("trace") or []
        out.append({
            "vuln_type": item.get("vulnerability_type") or item.get("vuln_type") or item.get("type"),
            "severity": (item.get("severity") or item.get("confidence") or "medium"),
            "file": item.get("file") or item.get("file_path"),
            "line": item.get("line") or item.get("line_number"),
            "sink": item.get("sink") or item.get("function"),
            "source_chain": [
                {"file": s.get("file"), "line": s.get("line"), "symbol": s.get("symbol")}
                if isinstance(s, dict) else {"raw": str(s)}
                for s in (chain if isinstance(chain, list) else [])
            ],
            "explanation": item.get("explanation") or item.get("description"),
            "raw": item,
        })
    return out


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_xvulnhuntr(
        repo_path: str,
        language: str = "auto",
        max_files: int = 50,
        timeout: int = 1800,
    ) -> dict:
        """LLM-chain SAST via xvulnhuntr (CompassSecurity fork — Python+C#+Java AST).

        Walks source files, traces input→sink chains, asks an LLM to confirm
        exploitable paths. Produces findings with file:line:sink chains that
        feed into save_finding.evidence.source_chain.

        Args:
            repo_path: local checkout path.
            language: 'python' | 'csharp' | 'java' | 'auto' (autodetect).
            max_files: cap on files analysed.
            timeout: seconds (LLM analysis is slow).
        """
        if not Path(repo_path).exists():
            return {"error": f"repo_path not found: {repo_path}"}
        if not _check_tool("xvulnhuntr"):
            return {"error": "xvulnhuntr not installed", "hint": _XVULNHUNTR_HINT}

        cmd = ["xvulnhuntr", "--repo", repo_path, "--output-format", "json", "--max-files", str(max_files)]
        if language != "auto":
            cmd.extend(["--language", language])
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return {
                "error": f"xvulnhuntr non-JSON output (rc={rc})",
                "stderr_tail": err[-1000:] if err else "",
                "stdout_tail": out[-1000:] if out else "",
            }
        findings = _normalise_findings(data)
        sev_count: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "medium").lower()
            sev_count[sev] = sev_count.get(sev, 0) + 1
        return {
            "repo_path": repo_path,
            "language": language,
            "total_findings": len(findings),
            "severity_count": sev_count,
            "findings": findings[:max_files],
            "tool": "xvulnhuntr",
        }

    @mcp.tool()
    async def run_vulnhuntr(
        repo_path: str,
        max_files: int = 50,
        timeout: int = 1200,
    ) -> dict:
        """LLM-chain SAST via vulnhuntr (Protect AI — Python only).

        Lighter / faster than xvulnhuntr but limited to Python. Useful for
        Python-only targets or cross-checking xvulnhuntr findings.

        Args:
            repo_path: local checkout path (must contain Python source).
            max_files: cap on files analysed.
            timeout: seconds.
        """
        if not Path(repo_path).exists():
            return {"error": f"repo_path not found: {repo_path}"}
        if not _check_tool("vulnhuntr"):
            return {"error": "vulnhuntr not installed", "hint": _VULNHUNTR_HINT}

        cmd = ["vulnhuntr", "-r", repo_path, "--output", "json"]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return {
                "error": f"vulnhuntr non-JSON output (rc={rc})",
                "stderr_tail": err[-1000:] if err else "",
                "stdout_tail": out[-1000:] if out else "",
            }
        findings = _normalise_findings(data)
        sev_count: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "medium").lower()
            sev_count[sev] = sev_count.get(sev, 0) + 1
        return {
            "repo_path": repo_path,
            "total_findings": len(findings),
            "severity_count": sev_count,
            "findings": findings[:max_files],
            "tool": "vulnhuntr",
        }
