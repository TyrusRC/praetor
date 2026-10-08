"""run_mantis — mantis is Praetor's source-audit engine (it replaced run_opengrep_source).

mantis runs OpenGrep plus a multi-engine layer, semantic-dedups, applies
`.mantisignore` suppressions, and — with llm=True and a provider key — adds
per-finding TRUE/FALSE triage and deep review (CWE/CVSS/PoC, call-graph
reachability). Offline by default (engines='none').

Praetor drives the mantis CLI as a subprocess and reads its JSON run file, so
Praetor's runtime stays free of mantis's deps (litellm/tree-sitter); the _llm
config is bridged into mantis's native provider env, exactly as source_aware
does for vulnhuntr.
"""
from __future__ import annotations

import glob
import json
import os
import re

from mcp.server.fastmcp import FastMCP

from ._runtime_guard import wrap_untrusted
from .recon._common import _check_tool, _run_cmd
from .source_aware import _llm_key_hint

# Positional modes mantis accepts after the path.
_MODES = {"quick", "deep", "bugbounty", "cve", "mobile", "web", "desktop",
          "llm", "taint", "secrets", "iac", "cloud"}

# opengrep/mantis severities → a stable worst-first order for the summary.
_SEV_ORDER = {"ERROR": 0, "CRITICAL": 0, "HIGH": 1, "WARNING": 2, "MEDIUM": 2,
              "WARN": 2, "LOW": 3, "INFO": 4}


def _find_json_report(stdout: str, repo_path: str) -> str | None:
    """mantis prints `[mantis] wrote <path>.json`; fall back to the newest run."""
    for m in re.finditer(r"wrote\s+(\S+\.json)", stdout):
        if os.path.isfile(m.group(1)):
            return m.group(1)
    runs = glob.glob(os.path.join(repo_path, ".mantis", "runs", "*.json"))
    return max(runs, key=os.path.getmtime) if runs else None


def _summarise(doc: dict, repo_path: str) -> str:
    findings = doc.get("findings") or []
    totals = doc.get("totals") or {}
    if not findings:
        return (f"mantis: no findings for {repo_path} (raw "
                f"{totals.get('raw_findings', 0)}, triaged {totals.get('triaged', 0)}, "
                f"status {doc.get('status', '?')}).")
    findings.sort(key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).upper(), 5))
    lines = [f"mantis findings for {repo_path} ({len(findings)}; raw "
             f"{totals.get('raw_findings', len(findings))}, status {doc.get('status', '?')}):", ""]
    for f in findings[:50]:
        sev = str(f.get("severity", "?")).upper()
        verdict = f.get("verdict")
        vtag = f" [{verdict}]" if verdict else ""
        lines.append(f"  [{sev}]{vtag} {f.get('rule_id', '?')}")
        loc = f.get("path", "")
        if f.get("start_line"):
            loc = f"{loc}:{f['start_line']}"
        if loc:
            lines.append(f"       → {loc}")
        msg = (f.get("message") or "").strip().splitlines()
        if msg:
            lines.append(f"       {msg[0][:160]}")
        if f.get("cwe"):
            lines.append(f"       {f['cwe']}")
    if len(findings) > 50:
        lines.append(f"  ... and {len(findings) - 50} more")
    lines.append("")
    lines.append("Ingest into findings.json via import_scan_results (re-run with "
                 "--format sarif and fmt='sarif').")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def run_mantis(  # cost: expensive (SAST pipeline; deep LLM mode slower)
        repo_path: str,
        mode: str = "quick",
        llm: bool = False,
        since: str = "",
        engines: str = "none",
        timeout: int = 1200,
    ) -> str:
        """Run the mantis source-audit engine over a local source tree. Requires mantis installed.

        mantis is Praetor's source-audit engine (it replaced run_opengrep_source):
        OpenGrep + a multi-engine layer, semantic dedup, .mantisignore suppressions,
        and — with llm=True and a provider key — per-finding TRUE/FALSE triage plus
        deep review (CWE/CVSS/PoC, call-graph reachability). Offline by default.

        Args:
            repo_path: path to the source tree to audit
            mode: quick | deep | bugbounty | cve | mobile | web | desktop | llm | taint | secrets | iac | cloud
            llm: enable LLM triage + deep review (needs a provider key; Praetor's _llm config is bridged to mantis's native env)
            since: scan only files changed vs a git ref (e.g. 'main', 'HEAD~1', 'uncommitted', 'staged')
            engines: 'none' = OpenGrep-only offline (default); 'offline' = add trivy/grype with offline DBs; or a comma-separated engine list
            timeout: max seconds (default 1200; deep LLM runs are slow)
        """
        if not _check_tool("mantis"):
            return ("Error: mantis not installed. Install: pipx install mantis-sast "
                    "(and pipx install opengrep).")
        if not os.path.isdir(repo_path):
            return f"Error: not a source directory: {repo_path}"

        cmd = ["mantis", "audit", repo_path]
        if mode and mode in _MODES:
            cmd.append(mode)
        cmd += ["--format", "json"]
        if since:
            cmd += ["--since", since]
        if engines == "offline":
            cmd.append("--engines-offline")
        elif engines:
            cmd += ["--engines", engines]

        key_hint: str | None = None
        if llm:
            # Bridge Praetor's _llm config into mantis's native provider env.
            key_hint = _llm_key_hint("")
        else:
            cmd.append("--skip-llm")

        # Source audit makes no target HTTP — never route through Burp.
        stdout, stderr, code = await _run_cmd(cmd, timeout, bypass_proxy=True)

        jpath = _find_json_report(stdout, repo_path)
        if not jpath:
            tail = (stderr or stdout or f"exit {code}").strip()[-400:]
            hint = f" ({key_hint})" if key_hint else ""
            return f"mantis produced no JSON report (exit {code}){hint}. Output tail: {tail}"
        try:
            with open(jpath, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as e:
            return f"mantis JSON report unreadable at {jpath}: {e}"

        return wrap_untrusted(_summarise(doc, repo_path), source="mantis")
