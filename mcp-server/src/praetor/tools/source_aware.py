"""Source-aware vulnerability hunting wrappers (W7, T11).

When source is available (white-box / grey-box engagement), LLM-chain SAST
catches what regex-only rule engines miss. Two OSS wrappers exposed:

  - run_xvulnhuntr  : CompassSecurity/xvulnhuntr — Python / C# / Java / Go AST
                      chain tracing (non-Python needs the fork's codeExtractor).
  - run_vulnhuntr   : protectai/vulnhuntr — Python-only original. Used when
                      target is Python-only or as a baseline cross-check.

Both are driven by their REAL CLI (-r root, -a analyze-subpath, provider flag);
they print a text report (+ <tool>.log), so the wrapper hands back that report
when the tool does not emit JSON, rather than failing.

Both produce findings with `file:line:sink` chains we project into
save_finding.evidence.source_chain — closes the white-box gap surfaced in
W7 research (Praetor had no source-aware probe pipeline).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


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


_XVULN_LANGS = {"python", "csharp", "java", "go"}  # xvulnhuntr -l (GO added by the fork)
_VULN_LLMS = {"claude", "gpt", "ollama"}            # vulnhuntr -l provider
_XVULN_LLMS = {"claude", "gpt"}                      # xvulnhuntr --llm provider


def _parse_output(out: str, err: str, rc: int, tool: str, repo_path: str,
                  extra: dict) -> dict:
    """Both tools print a TEXT report (scratchpad / analysis / poc / confidence_score
    / vulnerability_types) and a `<tool>.log`; neither emits JSON on stdout by
    default. Try JSON first (in case a fork/version does), else hand back the raw
    report so the analysis is never silently dropped (the old wrappers errored here)."""
    data = None
    if out.strip():
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = None
    if data is not None:
        findings = _normalise_findings(data)
        sev_count: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity") or "medium").lower()
            sev_count[sev] = sev_count.get(sev, 0) + 1
        return {"tool": tool, "repo_path": repo_path, "format": "json",
                "total_findings": len(findings), "severity_count": sev_count,
                "findings": findings, **extra}
    report = (out or err).strip()
    if rc != 0 and not report:
        return {"tool": tool, "repo_path": repo_path, "error": f"{tool} failed (rc={rc})",
                "stderr_tail": (err or "")[-1000:], **extra}
    return {"tool": tool, "repo_path": repo_path, "format": "text", "rc": rc,
            "report": report[-8000:],
            "note": (f"{tool} emits a text report (+ {tool}.log), not JSON. The "
                     "analysis / poc / confidence_score (0-10; 8+ = high) / "
                     "vulnerability_types are in `report`; project a confirmed path "
                     "into save_finding.evidence.source_chain manually."),
            **extra}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_xvulnhuntr(
        repo_path: str,
        language: str = "python",
        analyze: str = "",
        llm: str = "claude",
        timeout: int = 1800,
    ) -> dict:
        """LLM-chain SAST via xvulnhuntr (CompassSecurity fork — Python/C#/Java/Go).

        Traces input→sink chains and asks an LLM to confirm exploitable paths for
        LFI / AFO / RCE / XSS / SQLI / SSRF / IDOR. Non-Python languages need the
        fork's `codeExtractor` helper on PATH (parses the syntax tree). Export
        ANTHROPIC_API_KEY (claude) or OPENAI_API_KEY (gpt) first.

        Args:
            repo_path: local checkout path (real flag: -r).
            language: python | csharp | java | go (real flag: -l, uppercased).
            analyze: optional file/subdir to scope the hunt (real flag: -a) —
                cheaper + faster than the whole repo.
            llm: claude (default) | gpt (real flag: --llm).
            timeout: seconds (LLM analysis is slow).
        """
        if not Path(repo_path).exists():
            return {"error": f"repo_path not found: {repo_path}"}
        if not _check_tool("xvulnhuntr"):
            return {"error": "xvulnhuntr not installed", "hint": _XVULNHUNTR_HINT}
        lang = (language or "python").lower()
        if lang not in _XVULN_LANGS:
            return {"error": f"language must be one of {sorted(_XVULN_LANGS)}"}
        if (llm or "claude").lower() not in _XVULN_LLMS:
            return {"error": f"llm must be one of {sorted(_XVULN_LLMS)}"}

        cmd = ["xvulnhuntr", "-r", repo_path, "-l", lang.upper(), "--llm", llm.lower()]
        if analyze:
            cmd += ["-a", analyze]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        return _parse_output(out, err, rc, "xvulnhuntr", repo_path, {"language": lang})

    @mcp.tool()
    async def run_vulnhuntr(
        repo_path: str,
        analyze: str = "",
        llm: str = "claude",
        timeout: int = 1200,
    ) -> dict:
        """LLM-chain SAST via vulnhuntr (Protect AI — Python only).

        Lighter than xvulnhuntr but Python-only; detects LFI / AFO / RCE / XSS /
        SQLI / SSRF / IDOR by tracing remote input to a sink. Needs Python 3.10
        (Jedi) and ANTHROPIC_API_KEY (claude) / OPENAI_API_KEY (gpt) /
        OLLAMA_BASE_URL (ollama). Good for a Python target or to cross-check
        xvulnhuntr.

        Args:
            repo_path: local checkout path (real flag: -r).
            analyze: optional file/subdir to scope the hunt (real flag: -a).
            llm: claude (default) | gpt | ollama (real flag: -l).
            timeout: seconds.
        """
        if not Path(repo_path).exists():
            return {"error": f"repo_path not found: {repo_path}"}
        if not _check_tool("vulnhuntr"):
            return {"error": "vulnhuntr not installed", "hint": _VULNHUNTR_HINT}
        if (llm or "claude").lower() not in _VULN_LLMS:
            return {"error": f"llm must be one of {sorted(_VULN_LLMS)}"}

        cmd = ["vulnhuntr", "-r", repo_path, "-l", llm.lower()]
        if analyze:
            cmd += ["-a", analyze]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        return _parse_output(out, err, rc, "vulnhuntr", repo_path, {})
