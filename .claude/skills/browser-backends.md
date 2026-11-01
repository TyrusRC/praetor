---
name: browser-backends
description: Pick the browser backend by TASK. CloakBrowser (headless, stealth, auto) = default for automated surface discovery — crawl, click everything, enumerate links. chrome-devtools-mcp (visible real Chrome the user watches) = default for observed/interactive testing and ALL OAuth / account / login flows (persistent real profile, logins survive). Load whenever a task needs a browser.
---

# Browser Backends

Two backends drive Chrome for Praetor. Both land every request in Burp proxy
history. They are NOT stacked — pick ONE per task, by what the task is.

| | **CloakBrowser** | **chrome-devtools-mcp** |
|---|---|---|
| Role | automated surface discovery | observed / interactive testing + **auth flows** |
| Tools | `browser_crawl` / `browser_navigate` / `browser_interact_all` / `browser_fill` / `browser_screenshot` / … | the `chrome-devtools` MCP server's tools |
| Visibility | headless | **visible Chrome the operator watches** (co-pilot) |
| Stealth | binary-patched anti-bot | none |
| Profile | ephemeral | **persistent real profile — logins survive runs** |
| Burp routing | **native** (launched with `proxy=Burp`) | launch Chrome via the helper below (`proxy=Burp`) |
| Seeing | screenshot + page info | screenshot **+ DOM/a11y snapshot + network panel** |

Both are DEFAULTS, each for its own job. This is a task split, not a
primary/fallback — do not ASK which to use, pick by the task.

## Policy — pick by the task

- **CloakBrowser = default for automated exploration.** Crawling a target,
  clicking every button, mapping all links/pages/routes, populating proxy
  history for a SPA/JS-heavy app → `browser_crawl` / `browser_interact_all`.
  MAY auto-trigger as part of recon without asking — headless, stealthy,
  Burp-routed.

- **chrome-devtools-mcp = default for observed testing and every auth flow.**
  Any OAuth / SSO / login / account / MFA / password-reset flow, anything the
  operator wants to watch and drive with Claude, or anything needing the live
  DOM/a11y snapshot or network panel → use the `chrome-devtools` tools against
  the visible Chrome. Reach for it WITHOUT asking when the task is auth-flow or
  "let me watch" shaped. It is NOT a fallback for CloakBrowser.

- **Why auth flows go here:** the visible Chrome runs a PERSISTENT REAL profile,
  so a Google/SSO session logged in once stays logged in across runs — no fresh
  profile, no re-login every session. That is the whole point of this lane.

## chrome-devtools-mcp — launch the Chrome it attaches to (once per session)

`.mcp.json` declares `chrome-devtools`, which ATTACHES to a Chrome on
`--browser-url=http://127.0.0.1:9222`. It does not launch one. Start that Chrome
with the helper — persistent real profile (logins survive) + routed through Burp
(traffic captured):

```
./scripts/launch-test-chrome.sh      # suggest the operator run it via the `! ` prompt prefix
```

Idempotent (no-op if 9222 is already up). Overrides: `PRAETOR_TEST_CHROME_PROFILE`
(default = your real Chrome profile), `PRAETOR_TEST_CHROME_PROXY` (default Burp
`:8080`), `PRAETOR_TEST_CHROME_BIN`. For HTTPS through Burp, import Burp's CA into
that profile once; the `--insecure` flag adds `--ignore-certificate-errors` as a
stopgap. The real profile is a singleton — quit any other Chrome on it first.

If 9222 is not up when an auth-flow task needs it, ASK the operator to run the
helper (Rule 32a blocker) — do not silently fall back to CloakBrowser for a login
flow, and do not mark the flow tested.

## Which to reach for

- crawl / "find all the links" / click everything / map the surface / anti-bot →
  **CloakBrowser** (`browser_crawl`, auto).
- OAuth / SSO / login / account / MFA / reset / "let me watch" / "drive it with
  me" / inspect DOM or network → **chrome-devtools-mcp** (visible Chrome).
