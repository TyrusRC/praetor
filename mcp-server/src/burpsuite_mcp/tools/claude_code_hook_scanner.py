"""scan_claude_code_project_hooks — CVE-2026-21852 class.

Claude Code (and AGENTS-compatible runners) load hooks declared in
`.claude/settings.json` / `.claude/settings.local.json` and execute their
`command` field during PreToolUse / PostToolUse / SessionStart events.

Risk: when an attacker plants a malicious `.claude/settings.json` in a project
the operator opens, the hook runs on first open without prompting — zero-prompt
RCE.

This is a static project-tree scanner. It walks every `.claude/settings*.json`
under a given root and classifies hook commands by risk: critical (shell
metachars, network, encoded payloads, suspicious download), high (unsigned
binary path, /tmp/, env-var-injected command), medium (any external command).

Returns dict with findings list. Does NOT execute or fetch anything.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP


_SETTINGS_GLOB_NAMES = (
    "settings.json", "settings.local.json", "config.json",
)

# Strict-critical: combinations that scream RCE delivery
_CRITICAL_PATTERNS = [
    (re.compile(r"\bcurl\b.*\|\s*(sh|bash|zsh)", re.IGNORECASE),
     "curl-pipe-shell — staged RCE delivery"),
    (re.compile(r"\bwget\b.*\|\s*(sh|bash|zsh)", re.IGNORECASE),
     "wget-pipe-shell — staged RCE delivery"),
    (re.compile(r"\beval\b", re.IGNORECASE),
     "eval — dynamic shell evaluation"),
    (re.compile(r"\bbase64\b\s+-d|base64\s*--decode", re.IGNORECASE),
     "base64 decode — obfuscated payload delivery"),
    (re.compile(r"python\s+-c\s+[\"']", re.IGNORECASE),
     "python -c inline — arbitrary code execution"),
    (re.compile(r"node\s+-e\s+[\"']", re.IGNORECASE),
     "node -e inline — arbitrary code execution"),
    (re.compile(r"\bnc\s+.*-e", re.IGNORECASE),
     "netcat -e — reverse shell setup"),
    (re.compile(r"/dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/\d+"),
     "/dev/tcp redirect — bash-native reverse shell"),
]

# High-risk: external network / writable paths / env-controlled
_HIGH_PATTERNS = [
    (re.compile(r"\bcurl\b|\bwget\b|\bhttpie\b", re.IGNORECASE),
     "network fetch in hook"),
    (re.compile(r"(^|\s)/tmp/[^\s]+", re.IGNORECASE),
     "/tmp/ path — writable by other users"),
    (re.compile(r"\$\{?[A-Z_]+_PATH\b"),
     "env-controlled binary path"),
    (re.compile(r"\bssh\b.*@", re.IGNORECASE),
     "outbound ssh in hook"),
    (re.compile(r"\bgit\s+clone\b", re.IGNORECASE),
     "git clone in hook — pulls external code"),
]

# Hook event types that fire WITHOUT operator approval on first open
_AUTOLOAD_EVENTS = (
    "SessionStart", "UserPromptSubmit", "PreToolUse",
    "PostToolUse", "Notification", "Stop", "SubagentStop",
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def scan_claude_code_project_hooks(
        project_path: str = ".",
        max_depth: int = 4,
        include_home_global: bool = True,
    ) -> dict:
        """Static scan for risky Claude Code / agent-runner hooks (CVE-2026-21852 class).

        Walks `project_path` for `.claude/settings*.json` (and similar)
        files; classifies each hook entry by risk. Does NOT execute
        anything.

        Args:
            project_path: project root to scan (default cwd).
            max_depth: directory walk depth limit (default 4).
            include_home_global: also scan `~/.claude/settings.json` etc.
                (default True — global hooks fire on every project).

        Returns:
            {
              "scanned_files": [str, ...],
              "hooks_total": int,
              "findings": [
                {"severity": "critical|high|medium|low",
                 "file": str, "event": str, "command_excerpt": str,
                 "matched": [str, ...], "matcher_text": str},
                ...
              ],
              "summary": str,
            }
        """
        roots: list[Path] = [Path(project_path).expanduser().resolve()]
        if include_home_global:
            home_claude = Path.home() / ".claude"
            if home_claude.exists():
                roots.append(home_claude.resolve())

        scanned: list[str] = []
        findings: list[dict] = []
        hooks_total = 0

        for root in roots:
            for settings_path in _iter_settings(root, max_depth):
                scanned.append(str(settings_path))
                try:
                    data = json.loads(settings_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if not isinstance(data, dict):
                    continue
                hooks = data.get("hooks")
                if not isinstance(hooks, dict):
                    continue
                for event_name, event_entries in hooks.items():
                    if not isinstance(event_entries, list):
                        continue
                    for entry in event_entries:
                        if not isinstance(entry, dict):
                            continue
                        # Per Claude Code schema, hook entries carry a "hooks"
                        # sub-list with {type, command}.
                        sub_hooks = entry.get("hooks") or [entry]
                        if not isinstance(sub_hooks, list):
                            continue
                        for h in sub_hooks:
                            if not isinstance(h, dict):
                                continue
                            cmd = h.get("command") or ""
                            if not isinstance(cmd, str) or not cmd:
                                continue
                            hooks_total += 1
                            sev, matched, mtext = _classify(cmd, event_name)
                            if sev != "low":
                                findings.append({
                                    "severity": sev,
                                    "file": str(settings_path),
                                    "event": event_name,
                                    "command_excerpt": cmd[:200],
                                    "matched": matched,
                                    "matcher_text": mtext,
                                    "autoload": event_name in _AUTOLOAD_EVENTS,
                                })

        crit = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        autoload = sum(1 for f in findings if f.get("autoload"))
        summary = (
            f"scanned={len(scanned)} settings files, hooks={hooks_total}, "
            f"findings={len(findings)} (critical={crit}, high={high}, "
            f"autoload-event={autoload})"
        )
        return {
            "scanned_files": scanned,
            "hooks_total": hooks_total,
            "findings": findings,
            "summary": summary,
            "cve_class": "CVE-2026-21852",
        }


def _iter_settings(root: Path, max_depth: int):
    if not root.exists() or not root.is_dir():
        return
    root_depth = len(root.parts)
    # Direct .claude under root
    for sub in (root / ".claude", root):
        if sub.exists() and sub.is_dir():
            for name in _SETTINGS_GLOB_NAMES:
                p = sub / name
                if p.exists() and p.is_file():
                    yield p
    # Walk for nested .claude dirs (monorepos)
    for path in root.rglob(".claude"):
        try:
            depth = len(path.parts) - root_depth
            if depth > max_depth:
                continue
            for name in _SETTINGS_GLOB_NAMES:
                p = path / name
                if p.exists() and p.is_file():
                    yield p
        except (OSError, PermissionError):
            continue


def _classify(cmd: str, event: str) -> tuple[str, list[str], str]:
    matched: list[str] = []
    mtexts: list[str] = []
    for rx, txt in _CRITICAL_PATTERNS:
        if rx.search(cmd):
            matched.append(txt)
            mtexts.append(rx.pattern)
    if matched:
        return ("critical", matched, " | ".join(mtexts))
    for rx, txt in _HIGH_PATTERNS:
        if rx.search(cmd):
            matched.append(txt)
            mtexts.append(rx.pattern)
    if matched:
        return ("high", matched, " | ".join(mtexts))
    # Medium = autoload event with any non-builtin command
    if event in _AUTOLOAD_EVENTS:
        first = cmd.strip().split()[0] if cmd.strip() else ""
        if first and not first.startswith("/usr/bin/") and not first in (
            "echo", "true", "false", ":", "exit", "[",
        ):
            return ("medium", ["autoload-event with external command"], first)
    return ("low", [], "")
