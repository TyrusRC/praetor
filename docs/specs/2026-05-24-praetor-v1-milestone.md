# Praetor v1.0 Milestone — Plan

**Date:** 2026-05-24
**Goal:** Rebrand to **Praetor**, close the gaps identified in the competitive analysis (CAI / Noir / pentest-ai / Burp DAST AI), ship as v1.0.

## Architecture

```
Claude Code  <- stdio MCP ->  praetor-mcp (Python)  <- HTTP ->  praetor-burp-ext (Java)  <- Montoya ->  Burp Suite
                                  |
                                  +- subprocess: opengrep, gitleaks, trufflehog, git-dumper, Noir
                                  |
                                  +- persistent: .burp-intel/<domain>/
```

## Rename strategy — SOFT RENAME for v1.0

External identifiers (PyPI name, JAR name, display strings) become "Praetor". Internal Python package directory `burpsuite_mcp/` stays unchanged for v1.0 to avoid touching ~200 import statements and tests. Hard package rename deferred to v1.1 with a re-export shim. Result: users install `pip install praetor-mcp`, drop `praetor-burp-ext-1.0.0.jar` into Burp, see "Praetor" everywhere user-visible. Trademark exposure resolved.

**Files touched in rename commit:**
- `mcp-server/pyproject.toml` — `name`, `description`, script alias, version → 1.0.0
- `burp-extension/pom.xml` — `artifactId`, `name`, `description`, manifest `Implementation-Title`, version → 1.0.0
- `README.md` — title, badges, intro paragraph
- `setup.sh`, `doctor.sh` — header comments
- `skill.json` — `name`, `display_name`, `version`
- `CLAUDE.md` — "Project Overview" header
- `.mcp.json` — server name (`burpsuite-swiss-knife` → `praetor`), keep old MCP server name as alias if dual-keyed
- `MEMORY.md` — note rebrand fact

**NOT touched (deferred to v1.1):**
- `mcp-server/src/burpsuite_mcp/` directory and all its imports
- Java package `com.swissknife.*` — Java packages stay, only the JAR artifact name changes
- `.burp-intel/` directory structure (operator data, agnostic to product name)

## Wave breakdown

### Wave 1 — Rename + plan (this doc)
One commit. Tests run unchanged.

### Wave 2 — S-effort KB additions (single commit)
New KB JSONs (all at `mcp-server/src/burpsuite_mcp/knowledge/`):

| File | Contexts | Notes |
|---|---|---|
| `react_server_components.json` | RSC Flight protocol detection (`text/x-component`), CVE-2025-55182 React2Shell payload markers, CVE-2025-66478 Next.js boundary deserialization | Affects ~39% of cloud Next.js apps |
| `trpc_sspp.json` | `experimental_nextAppDirCaller`, `formDataToObject` SSPP, tRPC HTTP batch link, CVE-2025-68130 | `__proto__` / `constructor.prototype` matchers |
| `saml_xsw.json` | XSW1-8 sig-wrapping, comment injection in `NameID`, signature exclusion attack, KeyInfo manipulation | needs decode-base64-then-XML matcher |
| `oauth_chain_attacks.json` | mix-up attack, audience confusion, JWKS swap (`kid` header injection), PKCE downgrade, redirect_uri parser quirks | builds on existing `oauth.json` |
| `anon_cloud_expansion.json` | etcd 2379 (`/v2/keys/?recursive=true`), kubelet 10250/10255 (`/pods`, `/runningpods`), Docker daemon 2375/2376 (`/info`, `/containers/json`), Consul (`/v1/catalog/services`), Vault unsealed status, Nomad UI, Spinnaker, Firebase RTDB open-rules (`.json?shallow=true` returns object), Firestore unauthenticated read, Terraform `.tfstate` exposure, Lambda Function URL with `auth=NONE` | Pure HTTP probes |
| `nextjs_cache_poisoning.json` | `x-nextjs-stale-time`, RSC cache key manipulation, ISR poisoning, Server Action body confusion | 2025 research |

Update `_INDEX.md`. Bump KB count badge.

### Wave 3 — Reporting + intensity flag (single commit)

| Change | File |
|---|---|
| SARIF 2.1.0 exporter | `tools/notes/export_sarif.py` (new) |
| JUnit XML exporter | `tools/notes/export_junit.py` (new) |
| Compliance mapping JSON | `mcp-server/src/burpsuite_mcp/data/compliance_mappings.json` (new) — PCI-DSS / HIPAA / SOC2 / GDPR / OWASP-Top-10 tags per `vuln_type` |
| `intensity` flag on `assess_finding` + `auto_probe` + `save_finding` | `safe` / `normal` / `aggressive`. Safe-mode skips state-mutating probes (POST/PUT/DELETE/PATCH except idempotent), filters NEVER-SUBMIT inflation, requires Collaborator for OOB |
| `engagement_cost_cap` tool | `tools/intel/cost_cap.py` (new) — set per-domain ceiling ($USD + token), warn at 80%, hard-stop at 100% |
| `generate_repro_script` tool | `tools/notes/repro_script.py` (new) — render `repro.sh` from `logger_index` of saved finding. Curl command + expected response markers. Bundle in `export_report` |

### Wave 4 — Secrets + .git dump + opengrep (multiple commits)

| Tool | File | Behavior |
|---|---|---|
| `run_gitleaks` | `tools/secrets/gitleaks.py` (new) | Subprocess wrap, SARIF output, repo URL / path / staged mode |
| `run_trufflehog` | `tools/secrets/trufflehog.py` (new) | Subprocess wrap, `--verify` flag promotes `verified=true` → severity floor HIGH |
| `dump_exposed_git` | `tools/secrets/git_dumper.py` (new) | Wraps git-dumper, outputs to `.burp-intel/<domain>/git_dump/` |
| Auto-chain in `discover_common_files` | edit existing | `.git/HEAD` status 200 → ORANGE annotation → trigger dump → trigger gitleaks+trufflehog → save with `chain_with=[parent]` → CRITICAL if verified |
| `audit_crawled_artifacts` | `tools/analysis/opengrep_audit.py` (new) | opengrep over proxy-history JS/HTML bodies. Bundles `bsk/dom-clobbering.yml`, `bsk/prototype-pollution.yml`, `bsk/postmessage.yml` |
| `run_opengrep_source` | `tools/analysis/opengrep_source.py` (new) | SAST mode — repo path, ruleset selection, SARIF parse |
| Noir OpenAPI ingest | extend `tools/scope/import_scope.py` | New `--noir-json` flag; merges endpoint metadata into `.burp-intel/<domain>/endpoints.json` with `source: 'noir'` and `guards/sinks` arrays |

### Wave 5 — Active LLM/MCP probes + guardrail (single commit)

Promote reference-only KBs to active by removing from `_REFERENCE_ONLY`:
- `ai_prompt_injection.json`, `rag_injection.json`, `mcp_server_attacks.json`

Add new KB:
- `echoleak.json` — CVE-2025-32711 indirect-prompt-injection replay patterns (M365 Copilot family, Markdown image exfil, hidden HTML, CSS class injection)
- `vector_db_injection.json` — Chroma / Pinecone / Weaviate / Qdrant injection markers
- `mcp_tool_poisoning.json` — MCP-38 taxonomy: parasitic tool chaining, tool description prompt-injection, server identity spoofing

Add `tools/security/prompt_injection_guardrail.py` — middleware called by send-pipeline. Declarative filter rules (regex + token-count anomaly) for LLM-generated payloads before tool execution. Configurable via `set_program_policy(prompt_injection_filter='strict'|'normal'|'off')`.

### Wave 6 — HTTP/1.1 desync + SSPP (single commit)

| KB / change | Detail |
|---|---|
| `http_desync_2025.json` | Kettle DEFCON 33 / BH USA 2025: 0.CL, CL.0, V-H (visible TE), Expect-100-based, double-desync, RQP (request-queue poisoning). Raw-byte payloads with `unsafe_headers=True` |
| Extend `test_request_smuggling` | Add `variant=` parameter accepting any of the 6 new techniques. Reproduce primer harness via concurrent_requests |
| `sspp_blackbox.json` | Server-side prototype pollution black-box: Express / Fastify / Hapi `__proto__` JSON, `constructor.prototype.X` gadgets, execArgv RCE chain, Node `--experimental-vm-modules` flag toggle |
| Matcher | Status-code differential + length-delta + response-header-toggle compound matcher for SSPP detection |

### Wave 7 — Tests + docs + final commit/push

- Add unit tests per new tool (`tests/test_repro_script.py`, `tests/test_sarif_export.py`, `tests/test_gitleaks_wrap.py`, `tests/test_audit_crawled.py`, `tests/test_intensity_flag.py`).
- Add KB schema validation tests for the 11 new KB files.
- Build Java with `mvn clean package`.
- Run full Python test suite with `uv run python -m unittest discover tests`.
- Update README v1.0 section, doctor.sh tool detection (opengrep / gitleaks / trufflehog / git-dumper / noir), setup.sh install hints, skill.json badge.
- Update `MEMORY.md` with rebrand + v1.0 features.
- Commit each wave separately. Push origin/main at end.

## Success criteria

- `mvn clean package` produces `praetor-burp-ext-1.0.0.jar`
- `uv run python -m unittest discover tests` exits 0
- `./doctor.sh` shows opengrep / gitleaks / trufflehog / git-dumper / noir detection lines
- New tools callable via MCP (verify count: 218 + ~15 new = ~233 tools)
- All 11 new KB files schema-valid; loadable by `auto_probe`
- README + skill.json + pom + pyproject + CLAUDE.md show "Praetor" / "praetor"
- Public-facing tagline: "Praetor — agentic DAST orchestrator for Burp Suite"

## Non-goals for v1.0 (deferred to v1.1+)

- Hard rename of Python package `burpsuite_mcp/` directory
- Frida / Objection / MobSF mobile-dynamic primitives (L effort)
- gRPC / gRPC-Web protobuf engine (M effort)
- YAML playbook engine (M effort)
- Published Juice Shop benchmark + comparison table (M effort)
- OpenTelemetry tracing exporter (S effort)
- AD / BloodHound / impacket chain (strategic decision, out of stated scope)
- Swarm / auction multi-agent topology (M effort, extends grow-agent)

These remain in the agent-driven backlog for follow-up milestones.
