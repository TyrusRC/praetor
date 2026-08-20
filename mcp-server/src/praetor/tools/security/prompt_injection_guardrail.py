"""Prompt-injection guardrail middleware.

Declarative filter for LLM-generated payloads / responses. Designed to fire
between Claude Code (the brain) and the MCP tool (the hand) — catches three
failure modes:

  1. Indirect prompt injection in *responses* that Claude is about to feed
     back into reasoning (EchoLeak-class — Markdown image exfil, hidden HTML
     directives, 'ignore prior instructions' patterns).
  2. Dangerous-command requests Claude might generate when targets coerce
     it (destructive denylist overlap — already enforced server-side, this
     is a second tripwire at the MCP boundary).
  3. Cross-tool data exfiltration — LLM ferrying secrets from one tool's
     output into another tool's input.

Modes:
    off    — return verdict CLEAN unconditionally (operator opt-out)
    normal — flag but do not block (default; advisory)
    strict — flag and instruct the caller to abort

Operator binds the mode via set_program_policy(prompt_injection_filter=...)
or per-call via the inspect_for_prompt_injection tool below.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

# Pattern library — conservative on purpose. False-positives here are a UX
# tax. False-negatives are a security risk. Tune via tests, not vibes.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore_prior",       re.compile(r"(?i)ignore\s+(?:all\s+)?(?:prior|previous)\s+(?:instructions|prompts|system)")),
    ("system_override",    re.compile(r"(?i)(?:new|updated)\s+system\s+prompt\s*:")),
    ("act_as_jailbreak",   re.compile(r"(?i)\b(?:act|pretend|roleplay)\s+(?:as|like)\s+(?:DAN|jailbroken|unrestricted)")),
    ("override_role",      re.compile(r"(?i)override\s+(?:your|prior)\s+(?:role|instructions|guidelines)")),
    ("md_image_exfil",     re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]+\?[a-z]+=\{[^}]+\}\s*\)")),
    ("hidden_html_dir",    re.compile(r"<(?:div|span|p)[^>]*style=[\"'][^\"']*display\s*:\s*none[^\"']*[\"'][^>]*>\s*(?:[A-Z]{4,}|ignore|important)", re.IGNORECASE)),
    ("data_uri_html",      re.compile(r"<img[^>]+src=[\"']data:text/html[^\"']*[\"']", re.IGNORECASE)),
    ("system_tag",         re.compile(r"<\|im_start\|>\s*system|<\s*/?system\s*>|\[SYSTEM\]", re.IGNORECASE)),
    ("exfil_via_eval",     re.compile(r"(?i)(?:eval|setTimeout|setInterval|Function)\s*\(\s*['\"]?(?:fetch|XMLHttpRequest|navigator\.sendBeacon)")),
]

# Destructive overlap (Rule 5 enforces server-side too; this is an extra net
# at the MCP transport boundary).
_DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sql_drop",     re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE)),
    ("sql_delete",   re.compile(r"\bDELETE\s+FROM\s+\w+\s*(?:WHERE\s+1=1|;|$)", re.IGNORECASE)),
    ("sql_truncate", re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?\w+", re.IGNORECASE)),
    ("rm_rf",        re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\b")),
    ("shutdown",     re.compile(r"\b(?:shutdown\s+now|init\s+0|halt|poweroff|reboot)\b")),
    ("mkfs",         re.compile(r"\bmkfs\.[a-z0-9]+\b")),
    ("dd_zero",      re.compile(r"\bdd\s+if=/dev/(?:zero|urandom|random)")),
]


@dataclass
class GuardrailVerdict:
    state: str  # "clean" | "flagged" | "blocked"
    mode: str
    hits: list[tuple[str, str]]  # [(pattern_name, matched_text), ...]


def _scan(text: str, mode: str) -> GuardrailVerdict:
    if not text or mode == "off":
        return GuardrailVerdict("clean", mode, [])

    hits: list[tuple[str, str]] = []
    for name, pat in _INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append((name, m.group(0)[:120]))
    for name, pat in _DESTRUCTIVE_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append((f"destructive:{name}", m.group(0)[:120]))

    if not hits:
        return GuardrailVerdict("clean", mode, [])

    # strict mode = block any hit; normal = advisory flagged.
    state = "blocked" if mode == "strict" else "flagged"
    return GuardrailVerdict(state, mode, hits)


def _render(v: GuardrailVerdict) -> str:
    if v.state == "clean":
        return f"[CLEAN] guardrail (mode={v.mode}): no injection patterns matched."
    lines = [f"[{v.state.upper()}] guardrail (mode={v.mode}): {len(v.hits)} hit(s)"]
    for name, text in v.hits[:10]:
        lines.append(f"  {name}: {text}")
    if v.state == "blocked":
        lines.append("")
        lines.append(
            "Action: ABORT the proposed tool call. Operator must review "
            "(strict mode set via set_program_policy)."
        )
    else:
        lines.append("")
        lines.append(
            "Action: review. Mode=normal means advisory — operator may proceed "
            "but should validate the source. Set strict to hard-block."
        )
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def inspect_for_prompt_injection(
        text: str,
        mode: str = "normal",
    ) -> str:
        """Inspect a string for prompt-injection / destructive-command patterns.

        Call before feeding LLM-generated output back into tool calls, or before
        sending an LLM-generated payload to a target. Patterns cover EchoLeak,
        Markdown-image exfil, hidden HTML directives, system-tag spoofing,
        eval-driven beaconing, and destructive-command overlap (Rule 5).

        Args:
            text: The content to inspect.
            mode: 'off' / 'normal' / 'strict'. Default 'normal'.
        """
        mode = (mode or "normal").lower().strip()
        if mode not in {"off", "normal", "strict"}:
            return f"Error: mode must be off|normal|strict (got {mode!r})"
        verdict = _scan(text, mode)
        return _render(verdict)
