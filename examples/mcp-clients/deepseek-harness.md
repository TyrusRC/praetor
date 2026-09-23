# Praetor + DeepSeek Harness (dsh)

DeepSeek Harness ships a built-in MCP bridge — the `@deepseek-ai/dsh-mcp-client`
plugin — so Praetor plugs in as a standard stdio MCP server, exactly like Claude
Code or Codex. No native Cordis plugin is needed for the tools.

## 1. Prerequisites

- **Node.js** (dsh's runtime) and **`uv` / `uvx`** (launches Praetor's Python server;
  `curl -LsSf https://astral.sh/uv/install.sh | sh`).
- **Burp Suite running with the Praetor extension JAR loaded** (REST on `:8111`).
  dsh only starts the Python server — it does not touch Burp.

## 2. Install / run dsh

```sh
npx @deepseek-ai/dsh web        # from npm — opens the Web UI at http://127.0.0.1:3080
# or, from a source checkout:  pnpm dsh web
```

## 3. Register Praetor as an MCP server

dsh bridges MCP through its built-in `@deepseek-ai/dsh-mcp-client` plugin — add one
plugin row for Praetor. Put the row from
[`deepseek-harness-cordis.yml`](deepseek-harness-cordis.yml) in **either**:

- your profile's `cordis.yml` `plugins:` list (as the bare `- id: … name: … config: …`
  row shown in that file), **or**
- machine-wide in `$DSH_HOME/cordis.patch.yml` (default `~/.dsh/cordis.patch.yml`),
  wrapped in an `insert:` block:

  ```yaml
  - insert:
      - id: mcp-praetor
        name: '@deepseek-ai/dsh-mcp-client'
        config:
          serverName: praetor
          transport: stdio
          command: uvx
          args:
            - '--from'
            - 'git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server'
            - 'praetor-mcp'
          env: { BURP_API_HOST: '127.0.0.1', BURP_API_PORT: '8111' }
          toolCallTimeoutMs: 120000
  ```

Saving the config **hot-reloads** — the server connects with no dsh restart (the
first `uvx` launch is slow while it resolves deps). Praetor's tools then appear to the
model as `mcp__praetor__<tool>`:

```
mcp__praetor__list_tier1_tools   mcp__praetor__auto_probe
mcp__praetor__save_finding       mcp__praetor__list_skills   ...
```

## 4. Verify

```sh
dsh web --dump-config | grep -A3 praetor
zstdcat ~/.dsh/sessions/*/*/session*.jsonl.zstd | grep -E '"mcp__praetor__' | head
```

## 5. Rules, skills, agents on dsh — use the tools, not the resources

`dsh-mcp-client` bridges the MCP **Tools** capability only; **Resources and Prompts
are deferred**. So the `burp://rules/*` and `burp://skills/*` resources are invisible
on dsh — but everything Claude Code auto-loads from disk is also exposed as **tools**,
so dsh gets full parity. Call these; don't rely on resources:

- `mcp__praetor__praetor_bootstrap` → **call this first.** Returns the session-start
  flow (web / network / mobile lanes + the save-finding pipeline) and points to
  everything below. The one call that hands a non-Claude host the same operating
  context Claude Code loads natively.
- `mcp__praetor__get_rules` (`hunting` | `engineering`) → the always-active rule files.
- `mcp__praetor__list_skills` / `mcp__praetor__get_skill` (`name`) → procedural
  playbooks (verify-finding, chain-findings, lab-solve, …).
- `mcp__praetor__list_agents` / `mcp__praetor__get_agent` (`name`) → the agent-team
  strategy playbooks (pentest-commander, recon-agent, auth-tester, …). dsh spawns a
  sub-agent per playbook — give each the markdown from `get_agent` as its system
  prompt, exactly as Claude Code dispatches them.

Safety Rules 5–9 and the 7-gate save-finding pipeline are enforced in the tool layer,
so they hold on dsh regardless of what the agent loads. Discovery of the rest:
`mcp__praetor__list_tier1_tools` / `mcp__praetor__pick_tool`.

## 6. Steer the agent — a pentest protocol (the dsh-pentest pattern)

[`dsh-pentest`](https://github.com/howmp/dsh-pentest) drives its workflow by
injecting a system-prompt segment (`pentest:protocol`) into the agent and shipping a
preset. Do the same for Praetor: give your dsh pentest agent this operating protocol
in its preset / system prompt so it uses the tools under the HARD safety rules.

```text
You are a penetration tester operating the Praetor toolset over DeepSeek Harness.
Call mcp__praetor__praetor_bootstrap FIRST — it returns the flow and points to the
rules, skills, and agent playbooks. Load the full rules with
mcp__praetor__get_rules("hunting") and mcp__praetor__get_rules("engineering").
Capabilities are the mcp__praetor__* tools; find them with
mcp__praetor__list_tier1_tools / mcp__praetor__pick_tool. Load procedural playbooks
with mcp__praetor__list_skills then mcp__praetor__get_skill("<name>"); load agent
strategy playbooks with mcp__praetor__list_agents / mcp__praetor__get_agent("<name>").

Track the engagement as a lineage: call mcp__praetor__record_goal once, then
mcp__praetor__record_intent (a hypothesis) and mcp__praetor__record_fact (what you
observed) as you go, and mcp__praetor__link_finding after save_finding to hang the
proof on the intent that earned it. Mirror it into dsh-pentest's view with
mcp__praetor__engagement_graph(format="dsh").

HARD rules — always in force, never override:
1. Scope: call mcp__praetor__check_scope(url) before any request to a new domain;
   never send to / follow a redirect to an out-of-scope host.
2. No destructive payloads (no DROP TABLE / DELETE FROM / rm -rf / shutdown). Prove
   impact benignly: SELECT version() for SQLi, a read marker for RCE, an IDOR READ
   (never write) for access. Blind tests use SLEEP / math / Collaborator.
3. No breaking into accounts (credential-stuffing / ATO). Default creds are fine; ID
   enumeration is in-scope IDOR testing.
4. Never exfiltrate real user data; never modify another user's data.
5. Save-finding pipeline, in order: verify (replay >=3x for blind/timing) ->
   mcp__praetor__assess_finding (7-question gate) -> mcp__praetor__save_finding, each
   citing a real Burp proxy_history_index. There is no INFO tier — a
   leaked path / stack trace / version is an INPUT ("what does it let me reach?"),
   not a finding.
6. A tool safety-refusal (confirm_*) is a PIVOT, not a dead end — prove the same
   impact benignly instead of stopping.
7. Reports carry findings + impact only — no request counts, internal paths, or Burp
   indices in client output.
```

(The authoritative rules live in `.claude/rules/hunting.md` +
`.claude/rules/engineering.md`; the agent loads them verbatim with
`mcp__praetor__get_rules("hunting")` / `mcp__praetor__get_rules("engineering")`.)

## 7. Run Praetor + dsh-pentest together — same vocabulary, one bridge

Both model an engagement as `goal → intent → fact → finding → asset` with the same
edges (`spawns / yields / derived_from / proves / parent`). That is deliberate:
Praetor now has its own engagement-graph tools that mirror `dsh-pentest`'s domain
model, so the two interoperate instead of duplicating.

**Division of labour:** Praetor = the moves (recon / scan / exploit + the durable,
cross-session graph); dsh-pentest = the map (the live per-session web view).

Record the lineage as you hunt, with Praetor's tools (durable in
`.burp-intel/<domain>/engagement.json`, unlike dsh-pentest's single-session db):

```
mcp__praetor__record_goal(domain, target, objective, authorization)
mcp__praetor__record_intent(domain, "test IDOR on order_id")      -> intent-1
mcp__praetor__record_fact(domain, "order_id is sequential", "intent-1")
# ... run the save-finding pipeline (verify -> assess_finding -> save_finding) ...
mcp__praetor__link_finding(domain, "f007", "intent-1", ["asset-1"])
```

**Mirror it into dsh-pentest's live graph** with the built-in replay export — it
emits the exact `pentest_add_goal / _intent / _fact / _finding / _asset` calls in
dependency order (findings carry their reproducible steps, which dsh-pentest
requires):

```
mcp__praetor__engagement_graph(domain, format="dsh")
```

Have the dsh agent run those calls (or paste them) after a hunt to reproduce
Praetor's lineage in the `渗透` tab. Keep **Praetor's graph as the source of truth**
(it survives across sessions and feeds `generate_report`); dsh-pentest is the live
window. `format="mermaid"` gives the same picture anywhere Markdown renders, and
`format="text"` / `format="json"` for review or tooling.
