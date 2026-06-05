# cua-hunt — Computer-Use-Agent injection surface

Load when target is consumed by a Computer-Use Agent (Claude CUA, OpenAI Operator, ChatGPT Atlas browser, Sider, Comet, Genspark) OR when victim users are likely to drive a CUA through the app.

## Threat model

The target page is the **vector**, not the victim. An attacker plants instructions in CUA-readable channels (hidden DOM, aria-label, alt, title, noscript, off-screen, data-*). A human user sees nothing. A CUA reads the accessibility tree / OCRs the screenshot / dumps the DOM and **acts** on the injected instruction. RedTeamCUA (arXiv 2505.21936) shows 83% attack success on Claude 4.5 Opus CUA. OpenAI publicly conceded prompt injection in browser agents like Atlas "may never be solved."

This is stored-XSS-class severity *for CUAs*, even when no JS executes.

## Hunt loop

1. **Identify input → render path.** Where can user content be stored and later rendered into HTML/DOM seen by another user (or their CUA)? Comment fields, forum posts, profile bio, ticket descriptions, shared docs, channel messages, file metadata, calendar events.
2. **Passive scan first.** `probe_cua_injection_surface(url, mode="passive")` — fetches rendered HTML via CloakBrowser through Burp, greps the 7 CUA-readable channels for instruction-shape phrasing ("THIS IS IMPORTANT", "ignore previous", "you must first", "new task:", "SYSTEM:"). Returns VerdictResult.
3. **Active confirmation.** Generate Collaborator URL first (`generate_collaborator_payload()`). Then `probe_cua_injection_surface(url, mode="active", collaborator_url=..., plant_param=..., plant_endpoint=...)`. The probe plants a benign English canary (NO shell metacharacters, NO `document.cookie`, NO `curl|sh` — Rule 5 enforced at the builder layer) pointing at the Collaborator subdomain. If a CUA-driven re-navigation hits the Collaborator, the page is a CONFIRMED hijack vector.
4. **Cross-page persistence.** Plant on endpoint A. Read on endpoint B in the same CUA session. Marker reflection across endpoints + Collaborator hit on B = multi-step hijack confirmed. Use the `cua_multistep_persistence_2026` KB context.
5. **PII attribute leak.** `data-email` / `data-ssn` / `data-token` / `data-otp` rendered on profile pages. CUA browsing user account = OCR-able PII exfil surface. Severity MEDIUM standalone; HIGH when chained with #1-3.

## KB contexts (ai_prompt_injection.json)
- `cua_dom_hidden_instruction_2026` — primary scan
- `cua_multistep_persistence_2026` — cross-endpoint reflection
- `cua_data_attribute_pii_2026` — PII rendered in attributes

## Severity guidance (vs Rule 14)

| Finding | Standalone |
|---|---|
| CUA-instruction in hidden DOM, no state-change action | MEDIUM |
| CUA-instruction + reachable state-change endpoint | HIGH |
| CUA-instruction + Collaborator-confirmed action follow | CRITICAL |
| PII in data-* attribute alone | LOW |
| PII attribute + CUA-readable narrative pointing at it | HIGH (chain) |

## What to skip

- Don't claim CUA-XSS standalone. The exploit requires a CUA visitor. Without proof a target audience uses CUAs, mark SUSPECTED and chain.
- Don't fabricate the CUA. Verify with active-mode Collaborator hit, NOT by "looks injectable."
- Don't hunt with payloads carrying shell metacharacters or JS — Rule 5 (canary must be benign English narrative).

## Verification ladder (extends verify-finding.md)

1. Passive scan returns ≥1 cua_instruction hit → suspected.
2. Active scan plants benign canary → Collaborator hit within 60s → confirmed.
3. Second-endpoint reflection of marker → multi-step confirmed.
4. Save with `vuln_type='cua_dom_injection'`, include channel + endpoint in evidence.
