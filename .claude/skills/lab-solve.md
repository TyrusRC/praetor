---
name: lab-solve
description: Fast path for a single-objective lab/CTF (PortSwigger Web Security Academy, HTB, CTF) — one named vuln class with a hard solve condition. Skip recon/coverage/report machinery; go objective → class tool → confirm the solve flag.
---

# Lab Solve — single-objective fast path

For an engagement that names exactly ONE vuln class and has a hard solve
condition (a lab `is-solved` flag flips, a flag string appears). The opposite
shape from a bug-bounty hunt: the class is known up front and the deliverable is
the flipped flag, not a reportable finding.

> **When this applies:** the operator or a lab objective names ONE class AND a
> hard solve condition exists. If the class is unknown or the deliverable is a
> report, this is NOT a lab — use `hunt.md`. Scope/safety HARD rules (1–10) still
> apply in full.

## Skip (these are for open-ended engagements, not a one-class lab)

- Rule 20a recon-gate breadth and the `load_target_intel → discover_attack_surface`
  recon-first loop — a lab is one or two pages; read the objective, hit the named
  endpoint.
- Rule 19 full-coverage — test only the named class (Rule 19's lab exception).
- Phase 2.5 `capture_business_context`, Phase 3.6 deep-dive, Rule 27 creative
  hunting — no other classes to find.
- Rule 21/31 checkpointing + compaction survival — one short session.
- The Rule 10 save-finding pipeline: `assess_finding` / `save_finding` /
  `annotate_request` / `send_to_organizer` / screenshots / `compute_cvss`. A lab
  needs the solve flag, not a finding. Run these ONLY if the operator asks for a
  writeup.

## Flow

1. **Read the objective.** Fetch the lab root; the objective is in the
   `academyLabHeader` widget (PortSwigger) or the task text. It names the class,
   the target endpoint/param, and what "solved" means.
2. **Route the class → tool** (table below). Fire it at the one named
   endpoint/param. One correct exploit beats a sweep.
3. **Confirm the solve condition.** Re-fetch the lab root through Burp
   (`curl_request`) and check the status widget — no dedicated tool needed:
   `extract_regex(index, "is-solved|is-notsolved|Congratulations|solved the lab")`.
   `is-solved` / "Congratulations" ⇒ done, stop. Still `is-notsolved` ⇒ the action
   didn't land; fix the payload and repeat step 2 (Rule 13b: a non-flip is a real
   negative only once you've proven the payload reached the sink).

## Class → tool

| Lab class | First tool | Notes |
|---|---|---|
| SQLi (error/union) | `confirm_sqli`, `run_sqlmap` | `auto_probe(categories=['sqli'])` to locate |
| SQLi blind/boolean/time | `blind_sqli_extract` | oracle-driven extraction |
| XSS reflected/stored | `probe_xss_executed`, `run_dalfox` | needs executable context, not just reflection |
| XSS DOM | `analyze_dom`, `test_dom_sinks` | source→sink in JS |
| CSTI (Angular/Vue) | `auto_probe(categories=['xss'])` | `xss.json:angular` `{{7*7}}`→49 |
| SSTI | `confirm_ssti` | polyglot → engine probe |
| SSRF | `confirm_ssrf`, `test_ssrf` | Collaborator for blind |
| XXE | `confirm_xxe` | OOB via Collaborator for blind |
| OS command injection | `confirm_rce` | benign marker, not destructive |
| Path traversal / LFI | `test_lfi` | encoding + null-byte variants |
| Access control / IDOR | `test_auth_matrix`, `compare_auth_states` | ≥2 auth states |
| Auth / login / reset | `test_login_bypass`, `analyze_reset_tokens` | |
| JWT | `test_jwt`, `forge_jwt` | alg-none/confusion/kid |
| OAuth | `oauth_flow_simulator` | redirect_uri / state |
| CORS | `test_cors` | reflected origin + creds |
| CSRF | `test_csrf` | token/SameSite |
| Open redirect | `test_open_redirect` | header + body sinks |
| SSRF via Host / cache | `test_host_header`, `test_cache_poisoning` | HTTP/2 for cache-hit labs |
| Request smuggling | `test_request_smuggling` | CL.TE/TE.CL, `send_raw_request` |
| Prototype pollution | `test_prototype_pollution` | client + server |
| Race condition | `test_race_condition` | single-packet / last-byte |
| WebSocket | `test_websocket` | CSWSH handshake |
| GraphQL | `test_graphql` | introspection + `csrf_via_get` |
| Mass assignment | `test_mass_assignment` | hidden/nested fields |
| Deserialization | `generate_deserialization_gadget` | per-language gadget |
| Web LLM | `llm-agent` (dispatch) | multi-step chat, not `auto_probe` |

Unsure which tool a class maps to → `pick_tool('<class>')`. A public writeup for
the exact lab → `research_attack_vector`, then adapt (don't fire verbatim).
