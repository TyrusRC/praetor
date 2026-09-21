# Praetor agents on Gemini CLI

Praetor's agent roster is defined canonically in `.claude/agents/*.md` (loaded by
Claude Code's `Agent` tool). Gemini CLI has its own subagents feature
([docs](https://geminicli.com/docs/core/subagents/)) that uses the **same**
markdown-plus-frontmatter shape, so the roster ports directly.

The three files here (`recon-agent`, `finding-verifier`, `pentest-commander`) are
worked examples. Each is a **thin wrapper**: the frontmatter names the role, and the
body points the subagent at its canonical manual in `.claude/agents/<role>.md`, the
rules in `.claude/rules/`, and the Praetor MCP tools. Keeping the detail in
`.claude/agents/` means one source of truth — no second copy to drift.

## Use them

Place this directory at the project root (`.gemini/agents/`) or copy to
`~/.gemini/agents/` for all projects. Then:

- `/agents` — list configured subagents.
- `@recon-agent <task>` — invoke one directly (bypasses orchestrator routing).
- The main agent also delegates to them automatically via `invoke_subagent`.

## Port another role

Copy the pattern for any of the ~20 roles in `.claude/agents/`:

```markdown
---
name: <role>
description: <one line — copy from .claude/agents/<role>.md frontmatter>
---

You are **<role>** for the Praetor harness, running as a Gemini CLI subagent.
Operate through the Praetor MCP tools. Your operating manual is
`.claude/agents/<role>.md` — read it before acting. Load playbooks with
`get_skill("<name>")`; rules are in `.claude/rules/`. HARD rules always apply
(see `GEMINI.md`).
```

Other hosts: Cursor background agents and Antigravity's agent manager can each take
one role the same way (point the agent at `.claude/agents/<role>.md` + the MCP
tools). Hosts without subagents run a role as a single focused prompt — the tools
and rules are identical, you just lose automatic parallel dispatch.
