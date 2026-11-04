# Praetor agents on opencode

Praetor's agent roster is defined canonically in `.claude/agents/*.md`. opencode
has native [subagents](https://opencode.ai/docs/agents/) that use the same
markdown-plus-frontmatter shape under `.opencode/agent/`, so the roster ports
directly.

Every `<role>.md` here is **generated** by `scripts/sync_agents.py` from the
canonical manual. Each is a **thin wrapper**: the frontmatter sets
`mode: subagent` and the one-line description; the body points the subagent at its
operating manual in `.claude/agents/<role>.md`, the rules in `.claude/rules/`, and
the Praetor MCP tools. The detail stays in one place — no second copy to drift. Do
not hand-edit these files; edit `.claude/agents/<role>.md` and regenerate.

## Regenerate

```bash
uv run python scripts/sync_agents.py --harness opencode   # rewrite this dir
uv run python scripts/sync_agents.py --check              # CI: fail if stale
```

## Use them

Place this directory at the project root (`.opencode/agent/`) or copy to
`~/.config/opencode/agent/` for all projects. Register the Praetor MCP server per
`README.md` → *Install into your agent*. Then:

- `@recon-agent <task>` — invoke one directly.
- The primary agent also delegates to them via opencode's task/subagent routing.

opencode is frequently run single-model. Each wrapper states a host-agnostic **tier**
(`strategic` / `standard` / `fast`); map it to your configured model. On a
single-model host every role runs on that model and Rule 33's Opus escalation
becomes a no-op — the tools and HARD rules are identical.
