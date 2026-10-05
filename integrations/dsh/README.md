# Praetor dsh UI plugin (fork of dsh-pentest)

This is a Praetor-owned fork of [`howmp/dsh-pentest`](https://github.com/howmp/dsh-pentest)
(MIT). It renders Praetor's engagement graph as a native tab **inside dsh's web UI**.
You own it, so you customize the UI — this fork already applies a dark **Wiz-style**
security-graph theme. You do not depend on the upstream `@deepseek-ai/dsh-pentest`
packages.

Two packages:

- **`praetor-dsh-pentest`** — the server plugin. It defines the `pentest_add_*`
  tools and the `pentest` session projection. The tool names and the projection key
  are **unchanged from the upstream**, on purpose.
- **`praetor-dsh-ui-pentest`** — the browser plugin. It registers the view tab and
  renders the graph with React Flow. The Wiz theme lives in
  `src/client/*.module.css` — edit those files to restyle it.

## How the data gets in

Praetor is a Python MCP server. It does not ship a UI. The flow is:

1. You hunt. Praetor records the lineage (`record_goal` / `record_intent` /
   `record_fact` / `link_finding`).
2. You run `engagement_graph(domain, format='dsh')`. It returns an ordered list of
   `pentest_add_goal` / `pentest_add_intent` / `pentest_add_fact` /
   `pentest_add_finding` / `pentest_add_asset` calls.
3. The dsh agent runs those calls. They are the tools from `praetor-dsh-pentest`, so
   they fill the `pentest` projection.
4. `praetor-dsh-ui-pentest` reads that projection and draws the graph in the tab.

So Praetor supplies the moves. This fork supplies the map, inside dsh, under your control.

## Build

Read this before you build — the upstream is a **monorepo**, so these two packages
are not standalone-buildable as copied.

What is here and self-contained:
- Both packages' source (`src/`), `package.json`, and `tsconfig.json`.
- The base TypeScript configs, vendored into this folder: `tsconfig.base.json` and
  `tsconfig.base.client.json`. Each package's `tsconfig.json` extends them with a
  relative path (`../tsconfig.base.json`), so `tsc` resolves them here.

What is NOT here (upstream monorepo tooling):
- `praetor-dsh-ui-pentest/tsdown.config.ts` imports `../tsdown.client.ts` — a shared
  `clientBundle` build helper. That helper is **not in the upstream public source**
  (it is dsh dev tooling), so `npm run bundle` cannot run from this folder alone.

So build it one of two ways:

1. **Inside a dsh-pentest (or dsh) monorepo checkout — recommended, matches upstream.**
   Clone `howmp/dsh-pentest`, replace its `src/dsh-pentest` and `src/dsh-client-ui-pentest`
   with these two renamed, customized packages, then run the monorepo's own build. The
   shared `tsdown.client.ts` + workspace tooling are present there.
2. **Standalone (advanced).** Replace `praetor-dsh-ui-pentest/tsdown.config.ts`'s
   `clientBundle(...)` export with a plain `defineConfig({ entry, format: 'esm', dts: true,
   external: [<all peer deps>], plugins: [rawCssInline(...)] })`. The `rawCssInline` plugin
   in that file is already self-contained. Verify the output shape loads in your dsh.

Either way you need Node and the `@deepseek-ai/*` dsh runtime packages your dsh version uses.

## Install in dsh

Add two plugin rows to your dsh config (`~/.dsh/cordis.patch.yml` or `cordis.yml`),
pointing at the built local packages — the same way you add the Praetor MCP row.
Load `praetor-dsh-pentest` (server) and `praetor-dsh-ui-pentest` (web). Remove the
upstream `@deepseek-ai/dsh-pentest` + `@deepseek-ai/dsh-client-ui-pentest` rows if you
have them, so this fork replaces them (the tool and projection names match, so it is a
drop-in replacement).

Restart dsh. Open a pentest session. Run the Praetor hunt loop, then
`engagement_graph(format='dsh')`. The graph tab appears in the web UI.

## Customize

- **Theme (Wiz style):** edit `praetor-dsh-ui-pentest/src/client/ExploreView.module.css`
  and `PentestView.module.css`. The Praetor overrides are at the end of each file.
- **Layout / nodes / tabs:** edit the `*.tsx` views in `src/client/`.
- Re-run `npm run bundle` after each change.

## Version coupling (read this)

These plugins peer-depend on dsh's `@deepseek-ai/*` runtime at a pinned pre-release
(`0.1.0-rc.6` in the upstream). A newer dsh can change that API and break the build.
This is true of **any** dsh plugin, including the upstream dsh-pentest — a dsh plugin
always couples to dsh's version. When you upgrade dsh, bump these peer versions to
match and rebuild.

## Status

This fork is **source you build and test in your own dsh**. It was copied from the
upstream and rebranded + restyled here. It was **not built or run in dsh in this
environment** (no Node toolchain, no dsh instance). Verify the build and the load in
your dsh, and open an issue here with any API mismatch so the fork can track your dsh
version.

## License

MIT. Forked from [`howmp/dsh-pentest`](https://github.com/howmp/dsh-pentest) (MIT).
The upstream copyright and the MIT terms carry over. See each package's `package.json`.
