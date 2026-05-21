# Scope Relaxation + Smart Fuzzing + Novel KB Expansion

- Date: 2026-05-21
- Status: design approved, pending implementation plan

## Problem

1. **Scope blocks legitimate work.** Private contracts cannot be shared with Claude. Today Rule 1 is HARD-tier and tool-layer-enforced (`BaseHandler.requireInScope` wired into HttpSend, Session, Attack, Macro, Repeater, Resource, Fuzz). Operators on authorized pentest/RT engagements hit hard blocks because the bounty-program trust model is baked in everywhere.
2. **Hidden-path fuzz is spray.** `run_ffuf` runs against generic wordlists. High noise, low signal. No tech-stack filtering, no recon-derived priors.
3. **KB gap.** Knowledge base hasn't caught up with 2024–2026 novel surfaces (state-machine race, MCP-server attacks, edge-worker SSRF, DOM-clobbering 2024 variants, etc.).

## Trust model

This tool is a **scanner driven by an authorized operator** (analogous to Acunetix + AI), not a bounty-program gatekeeper. Scope authorization is the operator's responsibility; the tool defers and logs.

## Out of scope

- CIDR support → external nmap MCP + existing `run_httpx` + new `import_scope` covers it
- APT / C2 / lateral movement
- Network-tier (SMB / LDAP / Kerberos)
- Phishing-page clone, OAuth consent-grant attack (RT focus here = external-attacker bug-finding, not APT)

---

## Part A — Scope relaxation

### A1. Default mode flip

Single-tool change. Add `mode` param to existing `configure_scope`:

```
configure_scope(mode='operator', ...)   # NEW DEFAULT — warn-and-log
configure_scope(mode='strict', ...)     # OPT-IN — current Rule 1 hard-block
```

- Mode persists at `.burp-intel/_scope_mode.json` (survives sessions).
- `BaseHandler.requireInScope` checks mode first:
  - `strict` → current behavior unchanged
  - `operator` → `auditScope(url, tool, engagement)` appends to `.burp-intel/_audit.log` (JSONL) and returns true
- `assess_finding` Q1 defers to mode — operator mode trusts the domain on the finding.
- **Rules 5–9 stay HARD.** Destructive payload denylist in `confirm_*` unchanged. Brute-force, real-user-data exfil, modify-other-users — no relaxation. Only Rule 1–4 scope is relaxed.

### A2. Bulk import

New MCP tool:

```
import_scope(source: str, format: str = 'auto', engagement: str | None = None) -> dict
```

- Formats: `subfinder_txt`, `amass_json`, `httpx_json`, `plain` (newline-separated), `auto` (sniffs)
- One call adds N hosts to Burp scope
- Returns `{added: N, skipped: N, total: N, format_detected: str}`

### A3. Audit log

`.burp-intel/_audit.log` (JSONL, always on regardless of mode):

```json
{"ts":"2026-05-21T10:14:33Z","tool":"curl_request","url":"https://admin.client.com/api/users","host":"admin.client.com","host_first_seen":true,"mode":"operator"}
```

Operator's deliverable artifact ("every host I touched") — not Claude's gatekeeping mechanism.

---

## Part B — Smart fuzzing

### B1. SecLists detection

Extend existing `check_recon_tools`:

- Detect SecLists at: `$SECLISTS_PATH`, `/usr/share/seclists`, `/usr/share/SecLists`, `/opt/SecLists`, `~/SecLists`
- Cache resolved path to `.burp-intel/_seclists_path.json`
- If missing, return install hint:
  ```
  git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists
  export SECLISTS_PATH=/opt/SecLists
  ```

### B2. `generate_smart_wordlist`

New MCP tool:

```
generate_smart_wordlist(domain: str, tier: str = 'medium', extensions: list[str] | None = None) -> dict
```

Input sources:
- `.burp-intel/<domain>/fingerprint.json` → tech stack
- `.burp-intel/<domain>/endpoints.json` + sitemap + wayback → recon-derived path segments
- SecLists slices matched to detected tech:

| Detected tech | SecLists slice |
|---|---|
| PHP | `Discovery/Web-Content/PHP.fuzz.txt` |
| WordPress | `+ CMS/wordpress.fuzz.txt`, `+ wp-plugins.fuzz.txt` |
| Java / Spring | `Java.fuzz.txt`, `+ spring-boot.txt` (actuator) |
| Node | `nodejs.txt` |
| .NET / IIS | `IIS.fuzz.txt` |
| Django | `django.txt` |
| Rails | `rails.txt` |
| Generic / fallback | `common.txt` |

Tiers:
- `shallow` (~500): tech-matched + top-100 recon segments + extensions
- `medium` (~5k): + `directory-list-2.3-small.txt` slice
- `deep` (~50k): + `directory-list-2.3-medium.txt` + raft lists

Output: `.burp-intel/<domain>/_wordlists/fuzz-<tier>.txt` — deduped, ordered (recon-derived first, tech-specific next, generic last).

Returns: `{path, total, breakdown: {recon, tech, generic}}`.

### B3. ffuf chosen over gobuster

- JSON output (parseable by Python)
- MULTI fuzzing, body / header / vhost fuzz, regex matchers
- Active maintenance, ReconFTW / Bug-Bounty toolkit standard
- `run_ffuf` already registered — only wrap workflow

### B4. New skill + agent

- Skill: `.claude/skills/fuzz-hidden-paths.md`
  1. `detect_tech_stack(domain)` → save fingerprint
  2. `generate_smart_wordlist(domain, tier)` → wordlist path
  3. `run_ffuf(url, wordlist=path, match_codes=[200,204,301,307,401,403,500], filter_size=<baseline>)` → already routes through Burp proxy
  4. `annotate_request(idx, color='YELLOW', comment='<f-id> | hidden-path')` per hit
  5. `save_target_intel(domain, 'endpoints', new_hits)`
- Agent: add `fuzz-agent` to `AGENTS.md`. Role = hidden-path discovery with smart wordlists. Dispatch rules: never two on same host (WAF), max 1 concurrent per host.

---

## Part C — Knowledge base expansion (10 novel surfaces)

Each = JSON file under `mcp-server/src/burpsuite_mcp/knowledge/` with `contexts` + matchers. Integrated into `auto_probe` unless flagged reference-only.

| # | File | Surface | Origin | auto_probe |
|---|---|---|---|---|
| 1 | `state_machine_race.json` | Multi-step state desync (limit-overrun via timing-of-checks, two-window edges) | Kettle, "Smashing the State Machine" 2024 | yes |
| 2 | `h2_continuation_flood.json` | HTTP/2 CONTINUATION-frame DoS detection markers | CVE-2024-27316 | reference-only (DoS) |
| 3 | `oauth_dpop_confused_deputy.json` | DPoP token replay across resource servers | RFC 9449 + 2024 disclosures | yes |
| 4 | `mcp_server_attacks.json` | Tool-description prompt-injection, MCP rug-pull, MCP-to-MCP confused deputy | Anthropic MCP 2024–2026 | reference-only (situational) |
| 5 | `rag_injection.json` | RAG context poisoning via stored content, direct vector-DB injection | LLM-app pentest emerging | reference-only (context-heavy) |
| 6 | `edge_worker_ssrf.json` | Cloudflare Worker / Vercel Edge / Fastly Compute internal-header trust + same-zone SSRF | 2024–2025 disclosures | yes |
| 7 | `webauthn_passkey_attacks.json` | 0-click WebAuthn relay, cross-device passkey misbinding | DEFCON 2024 | yes |
| 8 | `cache_deception_v2.json` | Path-confusion variants (semicolon, encoded slash, fragment reflection) — extends `web_cache_deception` | Akamai 2024 | yes |
| 9 | `dom_clobbering_2024.json` | id/name → DOM property clobbering, HTMLCollection clobbering, 2024 sink list | PortSwigger 2024 | yes |
| 10 | `service_worker_attacks.json` | Offline cache poisoning, scope hijack, push-subscription steal | 2024 research | yes |

7 auto-probe-enabled, 3 reference-only.

---

## Tests

- `test_scope_mode_operator_logs.py` — operator-mode out-of-scope request appends to audit.log + proceeds
- `test_scope_mode_strict_blocks.py` — strict-mode still hard-blocks
- `test_import_scope_subfinder.py` — bulk import parses subfinder.txt + adds N hosts
- `test_import_scope_format_auto.py` — auto-format-sniff over each input shape
- `test_generate_smart_wordlist_php.py` — PHP fingerprint → PHP slice present, Java absent
- `test_generate_smart_wordlist_tiers.py` — shallow < medium < deep
- `test_seclists_detection.py` — SECLISTS_PATH override respected; common paths fallback
- `test_kb_new_files_load.py` — every new KB file parses + has required `contexts` and matchers
- `test_state_machine_race_matcher.py` — sample positive / negative
- `test_auto_probe_skips_reference_only.py` — `h2_continuation_flood` / `mcp_server_attacks` / `rag_injection` don't fire from `auto_probe`

## Counts after merge

| Category | Before | After |
|---|---|---|
| MCP tools | 215 | 217 (+`import_scope`, +`generate_smart_wordlist`) |
| Knowledge-base files | 103 | 113 (+10; 3 reference-only, 7 auto-probe) |
| Skills | 27 (actual count) | 28 (+`fuzz-hidden-paths`) |
| Agents | 9 | 10 (+`fuzz-agent`) |

## Doc updates

- `CLAUDE.md`: scope default = operator-mode; Rules 5–9 still HARD; ffuf hidden-path workflow paragraph
- `.claude/rules/hunting.md` R1: subsection "Engagement modes (operator vs strict)"; audit log noted as canonical
- `skill.json`: tool count 215→217, KB count 102→113, skill count, agent count
- `AGENTS.md`: `fuzz-agent` role + dispatch rules
- `mcp-server/src/burpsuite_mcp/knowledge/_INDEX.md`: regenerate
- `MEMORY.md`: bump tool/KB counts + note operator-mode default

## Implementation order

1. Part A (scope) — foundational; everything else assumes warn-and-log default
2. Part B (smart fuzzing) — independent of A
3. Part C (KB expansion) — independent; can run parallel to B once schemas locked
