# Praetor on DeepSeek Harness (DSH)

Native DSH support — **replaces the unmaintained `dsh-pentest` and
`dsh-reverse-skill` plugins**; nothing extra to install beyond Praetor itself.

## Why native
`dsh-pentest` gave DSH a pentest mode: an engagement graph
(goal→intent→fact→finding→asset), 9 tools, and a web UI. **Praetor already has all
of it** over the MCP server:

| dsh-pentest | Praetor (native) |
|---|---|
| `pentest_add_goal/intent/fact/asset` + `add_finding` | `record_goal` / `record_intent` / `record_fact` / `record_asset` / `link_finding` |
| edges spawns/yields/derived_from/proves/parent, `<kind>-<n>` ids | identical |
| `pentest_state` / `graph` / `report` | `engagement_graph` (text / report / json / **dsh** replay) |
| React web UI (flow / vulns / assets / report) | `engagement_graph(format='html')` → self-contained **Wiz-style** page |

`dsh-reverse-skill` bundled 87 reverse-engineering / binary / malware skills —
out of Praetor's authorized benign-PoC scope (web / network+AD / mobile / cloud),
so they are intentionally **not** included.

## Use it
1. Point DSH at this preset:
   ```
   dsh plugin --profile web add file:./dsh/preset/praetor
   ```
   (or mount `dsh/preset/praetor/` as a custom preset directory in your DSH config).
2. It registers **"Praetor Pentest Mode"**, launches the Praetor MCP server, and
   loads [`preset/praetor/instruction.md`](preset/praetor/instruction.md) as the
   mode protocol. The agent calls `praetor_bootstrap()` first and follows the
   engagement loop.

Works on any MCP-capable host (Claude Code, Codex, Gemini, DSH, …) — the preset is
just the DSH-flavoured entry point. See the repo root `README.md` for the full
tool surface.
