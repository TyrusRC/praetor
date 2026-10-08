# Rebrand + publish a Praetor dsh plugin (single-bundle, current upstream)

The upstream moved from the old two-package split (this folder's
`praetor-dsh-pentest` + `praetor-dsh-ui-pentest`, pinned to the stale
`0.1.0-rc.6` set) to a **single self-contained bundle package**,
`@howmp/dsh-pentest` (npm `latest` is `0.1.0-rc.36` as of this writing). dsh
loads that one published bundle. To ship a Praetor-branded, Wiz-themed plugin,
re-fork the current bundle and publish it under your own name.

## Why this is not built here

The themed **view bundle** (`lib/ui-pentest.client.js`, which carries the React
Flow views and the inlined Wiz CSS) is produced by DSH's internal client build
(`clientBundle` from `tsdown.client.ts`). That helper ships with the DSH dev
toolchain, **not** in the public `howmp/dsh-pentest` source — so the view bundle
cannot be rebuilt in a plain checkout. `scripts/build-client-entry.mjs` only
re-injects the registration entry into an already-built bundle. Run these steps
in an environment that has the DSH client build (your dsh dev setup).

## Steps

1. **Clone the current bundle at the version your dsh runs.**
   ```
   git clone https://github.com/howmp/dsh-pentest.git
   cd dsh-pentest
   npm install            # root pins cordis ^4.x etc. — installs from public npm
   ```

2. **Rebrand the package** (`package.json`):
   - `name`: `@howmp/dsh-pentest` → `praetor-dsh-pentest`
   - `repository.url`: → `git+https://github.com/TyrusRC/praetor.git`,
     `directory`: `integrations/dsh` (or wherever you keep the fork)
   - keep `publishConfig.access: public`, `exports`, `files`, and the `dsh`
     manifest (`bundle.patch` + `client.inject`) unchanged — dsh keys off those.
   - leave the tool names and the `pentest` projection key unchanged, so
     Praetor's `engagement_graph(format='dsh')` output still drives it.

3. **Apply the Wiz theme.** The Praetor overrides are the trailing blocks in this
   folder's `praetor-dsh-ui-pentest/src/client/*.module.css` (notably
   `PentestView.module.css` and `ExploreView.module.css`). Append those same
   override blocks to the current bundle's
   `src/dsh-client-ui-pentest/src/client/*.module.css`.

4. **Apply the English-only locale.** Drop the `zh` locale and keep `en` in
   `src/dsh-client-ui-pentest/src/client/locales.ts` (and the host preset copy
   under `preset/pentest/`), matching this fork.

5. **Rebuild** with the DSH client toolchain present:
   ```
   npm run bundle -w src/dsh-client-ui-pentest   # rebuilds lib/ui-pentest.client.js (needs clientBundle)
   npm run build:client-entry                    # re-injects the registration entry
   npm run build:preset-root                     # regenerates the preset
   npm test                                       # bundle patch-layer tests
   ```

6. **Validate the tarball** (no publish):
   ```
   npm pack --dry-run        # confirm lib/**, preset/pentest/**, cordis.patch.yml are present
   ```
   Load it in a real dsh and open a pentest session to confirm the themed tab
   renders — this is the step that cannot be done without a dsh instance.

7. **Publish** (public registry, irreversible — do this deliberately):
   ```
   npm whoami                # must be YOUR public npm account, never a work identity
   npm publish --access public
   ```

## Faster alternative (no publish)

The upstream `@howmp/dsh-pentest` bundle is already published and already renders
the operator's target + findings (Assets / Findings / Explore / Report tabs) from
Praetor's data. Install it in dsh and drive it with
`engagement_graph(domain, format='dsh')` — you get the UI now, maintained
upstream, with no fork to keep in sync. Re-fork only when you specifically want
the Praetor branding/theme published under your name.
