# Praetor agents on Gemini CLI

Praetor's agent roster is defined canonically in `.claude/agents/*.md` (loaded by
Claude Code's `Agent` tool). Gemini CLI has its own subagents feature
([docs](https://geminicli.com/docs/core/subagents/)) that uses the **same**
markdown-plus-frontmatter shape, so the roster ports directly.

Every `<role>.md` here is **generated** by `scripts/sync_agents.py` from the
canonical manual — the full roster, not a subset. Each is a **thin wrapper**: the
frontmatter names the role, and the body points the subagent at its canonical manual
in `.claude/agents/<role>.md`, the rules in `.claude/rules/`, and the Praetor MCP
tools. Keeping the detail in `.claude/agents/` means one source of truth — no second
copy to drift. Do not hand-edit these files; edit `.claude/agents/<role>.md` and
regenerate.

## Use them

Place this directory at the project root (`.gemini/agents/`) or copy to
`~/.gemini/agents/` for all projects. Then:

- `/agents` — list configured subagents.
- `@recon-agent <task>` — invoke one directly (bypasses orchestrator routing).
- The main agent also delegates to them automatically via `invoke_subagent`.

## Regenerate

The roster is regenerated from `.claude/agents/` — never hand-ported:

```bash
uv run python scripts/sync_agents.py --harness gemini   # rewrite this dir
uv run python scripts/sync_agents.py --check            # CI: fail if stale
```

Add a new harness by writing one `emit_<harness>` function in
`scripts/sync_agents.py` and registering it in `HARNESSES`.

Other hosts: Cursor background agents and Antigravity's agent manager can each take
one role the same way (point the agent at `.claude/agents/<role>.md` + the MCP
tools). Hosts without subagents run a role as a single focused prompt — the tools
and rules are identical, you just lose automatic parallel dispatch.
