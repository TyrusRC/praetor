---
name: browser-backends
description: Choose the browser backend — CloakBrowser (default, headless, stealth, auto) vs chrome-devtools-mcp (opt-in co-pilot, visible Chrome the user watches). Load when a task needs a browser and when the user asks to co-pilot / see / drive the browser.
---

# Browser Backends

Two backends drive Chrome for Praetor. Both must land every request in Burp
proxy history. They are NOT stacked — pick one per session.

| | **CloakBrowser** (default) | **chrome-devtools-mcp** (co-pilot) |
|---|---|---|
| Tools | `browser_navigate` / `browser_interact_all` / `browser_fill` / `browser_screenshot` / … | the `chrome-devtools` MCP server's tools |
| Visibility | headless | **visible Chrome the user watches** |
| Stealth | binary-patched anti-bot | none |
| Burp routing | **native** (launched with `proxy=Burp`) | only if the Chrome it attaches to was launched through Burp (see below) |
| Seeing | screenshot + page info | screenshot **+ DOM/a11y snapshot + network panel** |
| Who drives | Claude, via MCP tools | Claude, via MCP tools |

## Policy

- **CloakBrowser is the default and MAY auto-trigger.** For SPA / JS-heavy
  targets, fire `browser_crawl` as part of recon without asking — it is headless,
  stealthy, and Burp-routed. This is unchanged.
- **chrome-devtools-mcp NEVER auto-triggers.** Use it ONLY when the user
  explicitly asks to co-pilot / watch / see / drive a visible browser with Claude.
- **When the user asks to co-pilot a browser, ASK which backend** (AskUserQuestion)
  before touching either — do not pick silently:
  - *CloakBrowser* — headless + stealth, nothing to set up, Burp guaranteed. Best
    for testing the server / anti-bot targets.
  - *chrome-devtools-mcp* — a visible Chrome the user watches Claude drive, with a
    DOM/a11y snapshot and network panel ("see directly"). Needs the one-time setup
    below and trades away stealth.
  Recommend CloakBrowser unless the user specifically wants to watch or wants the
  DOM/network inspection.

## chrome-devtools-mcp — route it through Burp (one-time)

The server is already declared in `.mcp.json` as `chrome-devtools`, attaching to a
Chrome on `--browser-url=http://127.0.0.1:9222`. That Chrome must be launched
through Burp or its traffic never reaches proxy history:

```
google-chrome \
  --proxy-server=http://127.0.0.1:8080 \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/cdp-burp \
  --ignore-certificate-errors        # or install Burp's CA into this profile
```

Then chrome-devtools-mcp's tools drive that visible window and everything is
captured in Burp. If the user has not launched it, tell them to run the above
(suggest the `! <command>` prompt prefix) — do not silently fall back to
CloakBrowser after they asked for co-pilot.

## Which to reach for

- Default / recon / anti-bot / "just test it" → **CloakBrowser** (auto).
- "let me watch", "co-pilot", "drive the browser with me", "show me the DOM /
  network" → **ask**, then **chrome-devtools-mcp** if chosen.
- Deep authenticated SPA state either can reach; scripted steps via
  `browser_interact_all` (CloakBrowser) capture the most requests fastest.
