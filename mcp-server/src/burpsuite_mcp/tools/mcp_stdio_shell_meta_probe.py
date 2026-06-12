"""probe_mcp_stdio_shell_meta — detection-only static analyzer.

MCP STDIO servers are invoked by argv concatenation in many client launchers.
When the launch command interpolates operator-supplied or config-supplied
strings (`server_name`, `args`, env vars) through `shell=True` or naive
join, shell metacharacters give an attacker on the config plane an
arbitrary-command primitive.

Anthropic has declined to patch this class — it's by-design per the STDIO
spec. Detection-only here; the tool DOES NOT EXECUTE anything.

Inputs:
  - command: the configured server command string OR an array.
  - args_template: optional args list (strings).
  - env: optional env dict.

Returns dict with findings list per metachar class. No verdict shape —
this is a config audit, not a probe.
"""

from __future__ import annotations

import re
from typing import Any

from mcp.server.fastmcp import FastMCP


# Each entry: (regex, severity, description)
_METACHAR_PATTERNS = [
    (re.compile(r";\s*\S"), "high", "command separator `;` — chains commands"),
    (re.compile(r"&&|\|\|"), "high", "boolean chain `&&` / `||`"),
    (re.compile(r"\|\s*\S"), "high", "pipe `|` — redirects stdout to another command"),
    (re.compile(r"`[^`]+`"), "critical", "backtick command substitution"),
    (re.compile(r"\$\([^)]+\)"), "critical", "$() command substitution"),
    (re.compile(r"<\([^)]+\)|>\([^)]+\)"), "high", "process substitution `<()` / `>()`"),
    (re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"), "medium",
     "${VAR} expansion — caller-controlled environment substitution"),
    (re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*"), "low",
     "$VAR expansion — environment substitution"),
    (re.compile(r"~[^/\s]+"), "low", "~user expansion"),
    (re.compile(r">\s*/"), "medium", "redirect to absolute path"),
    (re.compile(r"2>&1|&>"), "low", "stderr redirection"),
    (re.compile(r"\beval\b"), "critical", "eval — dynamic evaluation"),
    (re.compile(r"\bexec\b"), "high", "exec — replaces current shell"),
]

# Tokens that, when present in the args_template, indicate a user-injected
# value lands in argv without quoting.
_INJECTION_SINKS = (
    "{server_name}", "{name}", "{tool}",
    "{user}", "{operator}", "{client}",
    "{cwd}", "{path}",
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_mcp_stdio_shell_meta(
        command: str | list[str],
        args_template: list[str] | None = None,
        env: dict[str, str] | None = None,
        shell_invocation: bool = True,
    ) -> dict:
        """Static audit of MCP STDIO command for shell-metachar injection.

        Does NOT execute. Inspects command, args_template, env values for
        metachars + injection-sink placeholders.

        Args:
            command: command string (or list).
            args_template: argv parts that may carry caller-supplied
                placeholders.
            env: environment dict to check for shell-metachar values.
            shell_invocation: when True, treat the join as passed to
                `shell=True` — every shell metachar is in scope. When
                False, only command-substitution / backtick / eval matter.

        Returns:
            {
              "findings": [{severity, location, matched, evidence}, ...],
              "injection_sinks_used": [placeholder, ...],
              "shell_invocation": bool,
              "summary": str,
            }
        """
        findings: list[dict] = []
        sinks_used: list[str] = []

        if isinstance(command, list):
            for i, part in enumerate(command):
                _scan_value(part, f"command[{i}]", findings, shell_invocation)
        else:
            _scan_value(command or "", "command", findings, shell_invocation)
            for sink in _INJECTION_SINKS:
                if sink in (command or ""):
                    sinks_used.append(sink)

        if args_template:
            for i, part in enumerate(args_template):
                _scan_value(part, f"args[{i}]", findings, shell_invocation)
                for sink in _INJECTION_SINKS:
                    if sink in part:
                        sinks_used.append(sink)

        if env:
            for k, v in env.items():
                _scan_value(v, f"env[{k}]", findings, shell_invocation)

        crit = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        summary = (
            f"findings={len(findings)} (critical={crit}, high={high}), "
            f"injection_sinks={len(set(sinks_used))}, "
            f"shell_invocation={shell_invocation}"
        )
        return {
            "findings": findings,
            "injection_sinks_used": sorted(set(sinks_used)),
            "shell_invocation": shell_invocation,
            "summary": summary,
            "note": ("Anthropic has declined to patch this class — by-design "
                     "per the STDIO spec. Operator responsibility to quote "
                     "or use shell=False with execve directly."),
        }


def _scan_value(value: str, location: str, findings: list[dict], shell: bool) -> None:
    if not isinstance(value, str):
        return
    for rx, sev, desc in _METACHAR_PATTERNS:
        # When shell_invocation=False, only critical/high matter
        if not shell and sev in ("medium", "low"):
            continue
        for m in rx.finditer(value):
            findings.append({
                "severity": sev,
                "location": location,
                "matched": desc,
                "evidence": value[max(0, m.start() - 10): m.end() + 10],
                "pattern": rx.pattern,
            })
