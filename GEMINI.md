# Praetor — operating guide for Gemini CLI & Antigravity

Praetor is an authorized pentest / red-team harness. Its capabilities are the
**Praetor MCP tools** (register the server first — see `README.md` →
*Install into your agent*, or `examples/mcp-clients/`). This file is the portable
rule set; the full Claude-Code manual is `CLAUDE.md`, the agent roster is
`AGENTS.md`.

## Find capabilities and playbooks

- **Tools (what to run):** call `list_tier1_tools()` or `pick_tool(task)`. Web lane
  routes through Burp (`127.0.0.1:8111`); network lane bypasses Burp.
- **Skills (how to run it):** call `list_skills()` then `get_skill("<name>")` — the
  procedural playbooks (verify-finding, chain-findings, lab-solve, craft-payload,
  …). Same content is on `burp://skills/index` + `burp://skills/<name>` if you
  prefer resources, or read `.claude/skills/*.md` directly.
- **Rules:** `.claude/rules/hunting.md` + `.claude/rules/engineering.md` (also
  `burp://rules/hunting` / `burp://rules/engineering`). They are authoritative.

## HARD rules — always in force (never override)

1. **Scope.** Before any request to a new domain call `check_scope(url)`. Never send
   to / follow a redirect to an out-of-scope host.
2. **No destructive payloads.** No `DROP TABLE` / `DELETE FROM` / `rm -rf` /
   `shutdown`. Prove impact benignly: `SELECT version()` for SQLi, a read marker for
   RCE, an IDOR **read** (never write) for access. Use `SLEEP`/math/Collaborator for
   blind tests.
3. **No breaking into accounts.** Default creds (admin:admin) are fine; large
   credential-stuffing / ATO brute force is not. ID enumeration is IDOR testing and
   IS in scope.
4. **Never exfiltrate real user data, never modify another user's data.**
5. **Save-finding pipeline, in order:** `verify` (replay ≥3× for blind/timing) →
   `assess_finding` (7-question gate) → `save_finding`. Evidence must cite a real
   Burp `logger_index` / `proxy_history_index`. There is no INFO tier — a leaked
   path / stack trace / version is an INPUT ("what does it let me reach?"), not a
   finding on its own.
6. **A tool safety-refusal is a PIVOT, not a dead end.** The `confirm_*` tools refuse
   only irreversible target changes; prove the same impact benignly instead.
7. **Reports carry findings + impact only** — no request counts, no internal paths,
   no Burp indices in client output.

## Subagents (optional)

Gemini CLI subagents that mirror Praetor's roles live in `.gemini/agents/` — each is
a thin wrapper that points at `.claude/agents/<role>.md` and the tools above. Manage
them with `/agents`; invoke with `@<agent>`. If your host has no subagents, run the
role as a single focused prompt — the tools and rules are identical.

The Burp extension JAR must be loaded in Burp separately; the MCP client only starts
the Python server.
