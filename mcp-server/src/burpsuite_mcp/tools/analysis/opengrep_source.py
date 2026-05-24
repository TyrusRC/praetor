"""opengrep over a local source-code tree — SAST pass.

Source-mode complement to audit_crawled_artifacts (which runs against the
captured proxy traffic). Use when the operator has source access — same
engine, different input. Bundled custom rulesets are reusable here, and
registry rulesets (p/owasp-top-ten, p/security-audit, p/secrets, p/javascript,
p/python, p/java) are available via `extra_configs`.

Bundles a `--sarif` flag pivot — operator can pipe the SARIF straight into
CI gates without converting Praetor's text output.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd

from .opengrep_audit import _RULESET_DIR, _resolve_configs


_DEFAULT_CONFIGS = ("p/owasp-top-ten", "p/security-audit")


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_opengrep_source(
        target_path: str,
        rulesets: list[str] | None = None,
        extra_configs: list[str] | None = None,
        sarif: bool = False,
        timeout: int = 600,
    ) -> str:
        """Run opengrep against a local source-code tree.

        Args:
            target_path: Path to source root.
            rulesets: Shorthand ruleset names (see audit_crawled_artifacts).
                Default: empty list — relies on registry configs only.
            extra_configs: opengrep --config values (registry names / paths).
                Defaults to p/owasp-top-ten + p/security-audit if nothing is
                passed in rulesets OR extra_configs.
            sarif: If True, return SARIF JSON instead of text summary.
            timeout: Max seconds.
        """
        if not _check_tool("opengrep") and not _check_tool("semgrep"):
            return (
                "Error: opengrep (or semgrep fallback) not installed.\n"
                "Install: https://github.com/opengrep/opengrep#installation"
            )
        tool = "opengrep" if _check_tool("opengrep") else "semgrep"

        target = Path(target_path).expanduser()
        if not target.exists():
            return f"Error: target path not found: {target_path}"

        rulesets = rulesets or []
        extra_configs = extra_configs or []
        if not rulesets and not extra_configs:
            extra_configs = list(_DEFAULT_CONFIGS)

        cmd = [tool, "scan"] + _resolve_configs(rulesets, extra_configs)
        cmd += ["--metrics", "off"]
        if sarif:
            cmd += ["--sarif"]
        else:
            cmd += ["--json"]
        cmd.append(str(target))

        stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        if sarif:
            return stdout or f"[rc={rc}] {stderr[:500]}"

        try:
            report = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            return f"opengrep output not parseable JSON (rc={rc}):\n{stderr[:500]}"

        results = report.get("results") or []
        if not results:
            return f"run_opengrep_source: 0 findings in {target}."

        by_rule: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in results:
            rid = r.get("check_id") or "?"
            sev = (r.get("extra") or {}).get("severity") or "?"
            by_rule[rid] = by_rule.get(rid, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

        lines = [f"run_opengrep_source: {len(results)} findings in {target} via {tool}", ""]
        lines.append("By severity:")
        for sev, c in sorted(by_severity.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {c}x {sev}")
        lines.append("\nBy rule (top 25):")
        for rid, c in sorted(by_rule.items(), key=lambda kv: -kv[1])[:25]:
            lines.append(f"  {c}x {rid}")
        lines.append("\nSample (first 10):")
        for r in results[:10]:
            rid = r.get("check_id") or "?"
            path = r.get("path") or "?"
            line_n = (r.get("start") or {}).get("line") or 0
            snippet = ((r.get("extra") or {}).get("lines") or "")[:160]
            lines.append(f"  [{rid}] {path}:{line_n}\n    {snippet}")
        return "\n".join(lines)
