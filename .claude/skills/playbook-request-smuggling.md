---
description: HTTP request smuggling — CL.TE / TE.CL / TE.TE classics + Kettle 2025 endgame (0.CL / CL.0 / V-H / Expect / double-desync). Detection workflow, safe payloads, evidence ladder. Load when a Pro chain (CDN / WAF / origin) is in scope.
globs:
---

# HTTP Request Smuggling Deep-Dive

Load when: target is behind a CDN / WAF / reverse proxy AND has an origin server (i.e. ≥2 HTTP parsers in the pipeline). Smuggling is impossible against a single-parser stack.

## Variant inventory

### Classic (RFC 7230 era)

| Variant | Front parser | Back parser | Payload skeleton |
|---|---|---|---|
| **CL.TE** | uses `Content-Length` | uses `Transfer-Encoding` | `CL: 6\r\nTE: chunked\r\n\r\n0\r\n\r\nGPOST /admin...` |
| **TE.CL** | uses `Transfer-Encoding` | uses `Content-Length` | `TE: chunked\r\nCL: 4\r\n\r\n5c\r\nGPOST...0\r\n\r\n` |
| **TE.TE** | both honour TE; one fooled by header obfuscation | one fooled | `Transfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n...` |

### Kettle 2025 endgame (HTTP/1.1 Must Die)

| Variant | Trigger | Severity |
|---|---|---|
| **0.CL** | Front emits 0-length, back uses CL — smuggle prefix bytes into next request | Critical |
| **CL.0** | Front uses CL, back ignores body entirely — back sees concatenated next-request prefix | Critical |
| **V-H (Vary-Host)** | Origin caches per Vary, smuggle Host changes cache key | Critical |
| **Expect** | `Expect: 100-continue` interaction mismatch — front responds before back parses, smuggled bytes flow as new request | High |
| **RQP (Request Queue Poisoning)** | Smuggle bytes accumulate until queue boundary, next victim's request gets prefix | Critical (mass impact) |
| **Double-desync** | Chain CL.TE + TE.CL across two proxies → either-end exploitable | Critical |

### Specific CVEs (2024-2025)

- **CVE-2025-32094** (Akamai) — Akamai-specific CL.0 against specific origin configs. Test for it explicitly on Akamai-fronted targets.
- **CVE-2024-***  — multiple frontend WAFs added smuggling primitives in 2024.

## Detection workflow

1. **Confirm two-parser pipeline** — fetch a benign URL and look at `Server:` / `Via:` / `X-Cache:` / `X-Akamai-*` / `X-Amz-Cf-Id:` / `CF-RAY` headers. ≥2 distinct identifiers = two parsers.
2. **Safe timing probe (default)** — `test_request_smuggling(session, path)` runs CL.TE / TE.CL / TE.TE timing-based detection. Returns VerdictResult SUSPECTED on any timing-confirmed finding; CONFIRMED only after Collaborator verification.
3. **Binary tool wrapper** — `run_smuggle(target_url, ...)` shells out to the smuggle CLI for Kettle 2025 0.CL / CL.0 / V-H / Expect / RQP / double-desync. Wider coverage than the in-process probe.
4. **Verify with Collaborator** — for any candidate, smuggle a request whose backend processing fires a Collaborator interaction. Three replays minimum (Rule 10a).

## Safe vs unsafe payloads

**Safe** (timing-based detection — no side effects):
- `Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX` — backend's parser waits for the chunked terminator that never comes from frontend → timing delta.
- `Transfer-Encoding:  chunked` (double space) — same model with header obfuscation.

**Unsafe** (visible side effects on next victim — operator-only):
- Anything that POSTs to a state-changing endpoint via smuggle (`POST /admin/delete-account`).
- Anything that pollutes a shared cache with attacker content.

Rule 5: never destructive payloads. Smuggle a benign canary, never `DROP TABLE` / `DELETE` / `shutdown`. Use Collaborator for confirmation, not visible side effects.

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | Smuggled request reached internal endpoint (status delta) AND ≥3 replays consistent AND Collaborator confirmation OR cache-poisoning marker visible | yes (chain with next-victim-impact context) |
| **SUSPECTED** | Timing delta consistent across CL.TE / TE.CL probes but no Collaborator hit yet | NO save — escalate to OOB |
| **FAILED** | All variants return baseline timing | NO |

## Severity discipline

- Smuggling itself = HIGH-CRITICAL.
- Smuggling + bypass of front-end ACL to reach `/admin` = CRITICAL.
- Smuggling + cache poisoning for victim PII / XSS = CRITICAL (mass impact).
- Timing-only signal without Collaborator = SUSPECTED, not CONFIRMED.

## save_finding shape

```python
save_finding(
    vuln_type="request_smuggling",
    endpoint="https://target.com/",
    severity="critical",
    evidence={
        "logger_index": <smuggle-confirming index>,
        "collaborator_interaction_id": "<id>",
        "summary": "CL.TE smuggling — front-end Akamai uses Content-Length, origin (nginx) uses Transfer-Encoding. Smuggled GET /admin reaches origin and bypasses front-end ACL. Confirmed via Collaborator interaction on backend.",
        "variant": "CL.TE",
        "front_parser": "akamai",
        "back_parser": "nginx",
        "reproductions": [
            {"logger_index": ..., "elapsed_ms": ..., "status_code": ...},  # 3 minimum
            ...,
        ],
    },
)
```

## Chain patterns

- **Smuggle → internal admin route** = bypass front-end auth (Rule 17 chain for `auth_bypass`).
- **Smuggle → cache poisoning** = XSS / open_redirect / data leak to mass victims (Critical multiplier).
- **Smuggle + Host header injection** = poison cache key per Vary.
- **0.CL / CL.0 on Akamai** = full origin reach bypassing Akamai's policy engine (CVE-2025-32094).

## NEVER_SUBMIT traps

- Timing delta with no Collaborator = SUSPECTED, do not submit.
- Smuggling against a single-parser stack — find the second parser first.
- Smuggling that hits the same endpoint with the same auth — no impact escalation.
- Lab-only smuggle that doesn't work against real frontend cache.

## Related

- `knowledge/http_desync.json` — Kettle 2025 0.CL / CL.0 / V-H / Expect / RQP / double-desync contexts (W1-W5)
- `test_request_smuggling` — timing-based detection (W14 VerdictResult)
- `run_smuggle` — smuggle CLI wrapper (W5 binary tool integration)
- `chain-findings.md` — `smuggling_to_internal_route` progression
- Rule 5 — destructive denylist
- Rule 9a — Collaborator-only for OOB confirmation
- Rule 10a — reproductions[] ≥ 3 for timing/blind classes
