# Praetor

*Agentic pentest & red-team harness — web (Burp) + network/AD, one operator log.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/TyrusRC/praetor/releases)
[![Java](https://img.shields.io/badge/java-21%2B-blue)](https://adoptium.net/temurin/releases/?version=21)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio-blue)](https://modelcontextprotocol.io/)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows%20%7C%20wsl-blue)](#supported-platforms)

> **v1.0** — the repo is `github.com/TyrusRC/praetor`. Binaries: `praetor-mcp` (MCP server) and `praetor-burp-ext-<version>.jar` (Burp extension). The Python package directory is still `burpsuite_mcp/`; the import-path rename lands in v1.1.

Praetor is a Model Context Protocol (MCP) server that turns Claude Code (or any MCP-aware LLM client) into an agentic pentester and red-teamer across **two co-equal lanes**:

- **Web lane (Burp):** HTTP capabilities, scanner, sitemap, proxy history, and Collaborator, plus a knowledge-driven probe engine (128+ matchers), SAST + secrets layer (opengrep / gitleaks / trufflehog / git-dumper / Noir), and native vuln-class orchestrators. Every request routes through Burp, so every finding is replayable from the Burp UI and citable by Logger index.
- **Network / red-team lane:** advanced network recon and post-exploitation that Burp can't see — `run_network_recon` (a chained discover → service-aware enum → leads pipeline), `run_nmap`, a sanctioned runner for impacket / netexec / responder / bloodhound-python / certipy / kerbrute / enum4linux-ng / smbmap / evil-winrm, offline cracking (`crack_hashes`), and a reusable **credential store**. Every action is recorded in a **MITRE ATT&CK-tagged operator log** with **loot chain-of-custody** — the non-Burp evidence a red-team report cites in place of a Logger index.

Both lanes forward into **[Ghostwriter](https://github.com/GhostManager/Ghostwriter)** as the central reporting/oplog hub, and share one save-finding pipeline with persistent target memory. **Nothing in Praetor is an optional add-on tool** — the web stack (nuclei/ffuf/sqlmap/…) and the network stack (nmap/netexec/impacket/…) are both core.

## Authorized Use

This is an offensive security tool. Use only on systems where you have explicit written permission to test (bug bounty scope, signed penetration test, red team contract, internal lab). The authors are not responsible for misuse.

## Architecture

```
                                      ┌─ web lane ──> Java Burp extension <- Montoya -> Burp Suite
LLM client <- stdio MCP -> MCP server ┤                 (127.0.0.1:8111, proxy :8080)
                                      └─ network lane ─> nmap / impacket / netexec / responder / ...
                                                          (bypass Burp; operator log + loot)
                          both lanes ─> Ghostwriter (GraphQL) : central reporting / oplog hub
```

- **Web lane:** the Java extension exposes a REST API on `127.0.0.1:8111` and tunnels HTTP through Burp's proxy listener (`127.0.0.1:8080`), so every probe appears in Proxy history and carries a Logger index.
- **Network lane:** external tools run directly (TCP/SMB/LDAP/Kerberos — Burp can't proxy them); each run is recorded in the operator log (`.burp-intel/<domain>/network/oplog.jsonl`, ATT&CK-tagged) with output under `material/tool-output/` and captured secrets in `network/loot/`. That operator-log id is the evidence a network finding cites.
- The Python MCP server is a thin client the LLM speaks to via stdio.
- Target intelligence, the operator log, loot, and the credential store all persist under `.burp-intel/<domain>/` (gitignored).
- **Ghostwriter** (optional but core when present) is the reporting hub both lanes forward into via GraphQL.

## Features

- MCP tool surface covering recon, scan, exploit, browser, auth, research, and reporting.
- HTTP send tools that route through Burp's proxy (curl-style, raw, repeater, intruder, concurrent).
- Adaptive scan engine driven by a JSON knowledge base (matchers + craft guidance) mapped to OWASP Top 10 (Web / API / LLM / Mobile), OWASP WSTG, PayloadsAllTheThings, HackTricks Web + Cloud — see the [Coverage](#coverage) table.
- Native vuln-class orchestrators where no third-party covers the surface: `test_csrf`, `test_ssrf`, `test_ssti` (SSTImap-modeled, multi-phase: polyglot → math distinguisher → engine-specific capability probes → optional blind sleep), `test_xxe`, `test_websocket` (CSWSH upgrade-handshake), `test_prototype_pollution`.
- Native auth attack tooling with zero external deps: `forge_jwt` (8 attack modes), `crack_jwt_secret` (HS dictionary), `test_login_bypass`, `test_mfa_bypass`, `test_session_lifecycle`, `analyze_reset_tokens` (entropy + sequential detection).
- Third-party wrappers proxied through Burp: sqlmap, dalfox, commix, nuclei, ffuf, katana, subfinder, amass, wafw00f, arjun, gau, waybackurls, wpscan, nikto.
- **Network / red-team lane**: `run_network_recon` chains nmap discovery → service-aware enumeration → prioritized leads → auto-loot, and bridges discovered web services back to Burp. A sanctioned runner drives impacket / netexec / responder / bloodhound-python / certipy / kerbrute / enum4linux-ng / smbmap / evil-winrm; `crack_hashes` (offline hashcat/john) plus a credential store close the capture → crack → reuse loop. Every action is logged to a **MITRE ATT&CK-tagged operator log** with **loot chain-of-custody**, and forwards to **Ghostwriter**. HARD safety (Rules 5–9) refuses destructive/brute args; scope is engagement-mode-aware.
- **SAST + secrets layer (v1.0)**: `audit_crawled_artifacts` opengrep-over-proxy-bodies (DOM clobbering / proto pollution / postMessage), `run_opengrep_source` source-tree SAST, `run_gitleaks` + `run_trufflehog` (live verification = HIGH severity floor), `dump_exposed_git` chains with `discover_common_files` `.git/HEAD` to reconstruct repo + extract secrets. Noir OpenAPI ingest via `import_scope --format noir_json`.
- **Active LLM/MCP probes (v1.0)**: `ai_prompt_injection`, `rag_injection`, `mcp_server_attacks`, `mcp_tool_poisoning`, `vector_db_injection`, `echoleak` (CVE-2025-32711). Declarative prompt-injection guardrail (`inspect_for_prompt_injection`).
- **CI integration (v1.0)**: SARIF 2.1.0 + JUnit XML exporters, compliance-framework tags (OWASP / PCI-DSS / HIPAA / SOC2 / GDPR / CWE), `intensity=safe|normal|aggressive` flag, per-engagement cost cap (`set_engagement_cost_cap`), auto-PoC `generate_repro_script` rendering runnable curl from the finding's logger_index.
- Save-finding pipeline with a 7-question gate (`assess_finding`) and per-program policy overrides.
- **False-positive defenses**: payload-tied reflection-liveness (a payload reflected only HTML/JS-encoded is not XSS), dual-baseline access-control check (`compare_auth_states` probes unauthenticated — public data is not an IDOR), OOB-mandatory verdicts for blind classes (blind SSRF/XXE/XSS need a resolved Collaborator interaction), AND-composed matchers with baseline deltas, and ≥3× replay for timing/blind classes.
- Stealth headless browser ([CloakBrowser](https://github.com/CloakHQ/CloakBrowser) — patched Chromium binary with source-level fingerprint fixes, not JS shims) that proxies through Burp.
- Fast history queries: `get_proxy_count` (sub-ms), `since_index` tail polling, `host` exact-match filter, ByteArray in-place body search.
- Persistent target memory with staleness detection and cross-target pattern reuse.
- Operator override surfaces for severity, scope filter, NEVER-SUBMIT class, confidence floor.

## Requirements

**Core (both lanes):**

- Burp Suite Professional or Community Edition — web lane
- Java 21+, Python 3.11+ with [uv](https://docs.astral.sh/uv/), Go (for the ProjectDiscovery tools)
- An MCP-aware LLM client (Claude Code, Claude Desktop, etc.)
- **Web tools** (core, not optional): nuclei, ffuf, sqlmap, katana, subfinder, dalfox, httpx, amass, gau, waybackurls, wpscan, nikto, opengrep, gitleaks, trufflehog
- **Network / red-team tools** (core, not optional): nmap, netexec, impacket-scripts, responder, bloodhound-python, certipy, kerbrute, enum4linux-ng, smbmap, evil-winrm, hashcat, john, gobuster, seclists
- **Docker + Docker Compose** — for the Ghostwriter reporting hub

`./setup.sh` installs all of the above (Kali/Parrot via apt, other distros via apt/uv/go with clone fallbacks). `./doctor.sh` reports what's present. On Kali most tools are preinstalled or one `apt` away.

Best with Burp Professional (scanner control + Collaborator); Community degrades gracefully — see below.

### Burp Edition Compatibility

**Professional** — full support. Default target environment.

**Community** — supported with manual setup. Almost everything works because the extension and MCP server use Burp's Montoya API for HTTP/proxy/scope, not the Pro-only scanner pipeline. Pro-only features degrade gracefully:

| Pro-only feature | Tools that depend on it | Community workaround |
|---|---|---|
| Active scanner | `scan_url`, `crawl_target`, `get_scan_status`, `cancel_scan`, `get_scanner_findings`, `get_new_findings`, `get_issues_dashboard` | Use `auto_probe` (knowledge-driven sweep), `fuzz_parameter`, `fuzz_with_feedback`, and the native `test_*` orchestrators (`test_csrf` / `test_ssrf` / `test_xxe` / `test_websocket` / `test_prototype_pollution` / `test_login_bypass` / `test_mfa_bypass`). These run through the extension's HTTP API and do not require Burp's scanner. |
| Burp Collaborator | `generate_collaborator_payload`, `auto_collaborator_test`, `get_collaborator_interactions`, `collaborator_pool_status` | Operator supplies an OOB callback URL — interact.sh / webhook.site / requestcatcher.com / a self-hosted DNS box — and passes it explicitly into payloads. Rule 9a forbids fabricating domains. |
| Intruder at full speed | `send_to_intruder_configured` | Community throttles Intruder heavily. Use `concurrent_requests` (Python-side parallelism through Burp proxy) for legitimate parallel testing without the throttle. |

Run `check_pro_features()` at session start to confirm which Pro capabilities the operator's instance exposes — the MCP server detects them at runtime, so Community users get a clear "not available" message instead of a silent hang.

## Installation

Pick the level of automation you want.

### Quick — `uvx` (no clone needed for the MCP server)

The MCP server runs straight from the source tree with `uvx`. You still need the Burp extension JAR loaded in Burp Suite — see the Manual section below for that part.

```sh
uvx --from "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server" \
    praetor-mcp
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server",
        "praetor-mcp"
      ]
    }
  }
}
```

### Automated (full local checkout — extension + server)

```sh
./setup.sh        # Linux / macOS
./setup.ps1       # Windows PowerShell
./setup.bat       # Windows double-click
```

The script installs Java 21+, Maven, Python 3.11+, uv, Go where missing, builds the extension, installs the MCP server (which pulls CloakBrowser and warms its stealth Chromium download), optionally installs ProjectDiscovery tools, and writes `.mcp.json`.

Run `./doctor.sh` afterwards to verify the install.

### Manual

```sh
# 1. Build the Burp extension
cd burp-extension
mvn package
# Load target/praetor-burp-ext-1.0.0.jar in Burp: Extensions -> Add -> Java

# 2. Install the MCP server
cd ../mcp-server
uv venv
uv sync

# 3. Configure your MCP client (see below)
```

### `pipx`

```sh
pipx install "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server"
praetor-mcp                   # entrypoint
```

## Configuration

Create `.mcp.json` in the project root. The file is gitignored; each developer maintains their own.

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "/absolute/path/to/praetor/mcp-server/.venv/bin/python",
      "args": ["-m", "burpsuite_mcp"]
    }
  }
}
```

**Connection defaults — no config needed on a single host.** The extension's config tab defaults to Host `127.0.0.1`, Port `8111`, and the MCP server defaults to the same `127.0.0.1:8111`. When Burp and Claude Code run on the same machine (or on WSL with mirrored networking), the two align and the MCP auto-connects with nothing to change. Edit the tab's Host/Port only for the exceptions below: a non-default port, or reaching Burp across a host boundary (WSL NAT → bind `0.0.0.0`). Caller-supplied `BURP_API_HOST` / `BURP_API_PORT` env in `.mcp.json` override the client side.

On Windows replace the command with `C:\\...\\.venv\\Scripts\\python.exe`.

### WSL (Burp on the Windows host)

`./setup.sh` auto-detects WSL and its networking mode, then configures `.mcp.json` accordingly. Two modes:

- **Mirrored (recommended, secure).** Add to `%UserProfile%\.wslconfig`:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```
  then run `wsl --shutdown` in PowerShell and reopen WSL. Burp on Windows `127.0.0.1:8111` is now reachable from WSL as `127.0.0.1` — no env override, no bind change, nothing exposed off the host. Verify from WSL with Burp running: `curl -s http://127.0.0.1:8111/api/health`. Requires Windows 11 22H2+.
- **NAT (default).** Reach Burp via the Windows host IP (the WSL default-route gateway, e.g. `172.22.112.1`):
  1. Add an `env` block to `.mcp.json` setting `BURP_API_HOST` to that IP (setup.sh writes this for you).
  2. In the Praetor config tab set **Host = `0.0.0.0`**.
  3. Launch Burp with the JVM flag `-Dpraetor.allow_non_loopback_bind=true` — the extension refuses a non-loopback bind without it.

  NAT mode exposes the unauthenticated API on the WSL virtual switch; use only on a trusted host. Prefer mirrored.

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `BURP_API_HOST` | `127.0.0.1` | Burp extension API host |
| `BURP_API_PORT` | `8111` | Burp extension API port |
| `BURP_API_TIMEOUT` | `30` | HTTP timeout in seconds |
| `BURP_PROXY_HOST` | `127.0.0.1` | Burp proxy listener host |
| `BURP_PROXY_PORT` | `8080` | Burp proxy listener port |
| `GHOSTWRITER_URL` | — | Ghostwriter base URL (e.g. `https://127.0.0.1`); unset = no forwarding |
| `GHOSTWRITER_ADMIN_SECRET` | — | Hasura admin secret (or use `GHOSTWRITER_API_TOKEN`) |
| `GHOSTWRITER_OPLOG_ID` | — | numeric Oplog id to append entries to |
| `GHOSTWRITER_INSECURE_TLS` | `false` | `1` to accept Ghostwriter's self-signed localhost cert |

The Java extension also accepts JVM system properties `praetor.proxy.host` and `praetor.proxy.port` (highest precedence). `./setup-ghostwriter.sh` writes the `GHOSTWRITER_*` values into `.env` automatically (see [Ghostwriter setup](#ghostwriter-reporting-hub)).

## Usage

Once `.mcp.json` is loaded by your MCP client, the tools are available to the agent. Pick the lane that fits the target (or run both — a box often has web *and* network surface).

**Web lane (a webapp / API):**

1. `configure_scope` to set include/exclude patterns and auto-filter tracker domains.
2. `browser_crawl` or `discover_attack_surface` to map the target.
3. `auto_probe` to run knowledge-driven probes on parameters.
4. `assess_finding` → `save_finding` for each suspected issue.
5. `generate_report` to export findings.

**Network / red-team lane (a host, subnet, or AD environment):**

1. `run_network_recon(target, domain)` — one call: nmap discovery → per-service enum (SMB/LDAP/RPC/MSSQL/Kerberos) → **leads** (anon access, roastable hashes, SMB signing off, Pwn3d!) → auto-loots hashes → bridges any HTTP(S) service into the web lane. Add `creds='DOMAIN/user:pass'` to unlock authenticated enum.
2. `crack_hashes(domain, 'asrep', loot_type='asrep_hash')` — offline-crack captured hashes; cracked passwords auto-land in the credential store.
3. Re-run `run_network_recon` with the recovered `creds=` (or `run_network_tool` for a specific impacket/netexec action) to move laterally. The kill chain loops: **capture → crack → store → reuse.**
4. `get_operator_log(domain, 'timeline'|'attack'|'loot')` — the ATT&CK-tagged evidence base for the report.
5. `sync_to_ghostwriter(domain)` — forward both lanes' evidence into Ghostwriter.

Every network action is auto-recorded in the operator log; captured secrets get chain-of-custody in the loot store; a HARD safety layer (Rules 5–9) refuses destructive/brute args in both engagement modes, and scope is mode-aware (`configure_scope(mode='operator'|'strict')`).

The agent receives expert methodology through the skill files in `.claude/skills/`. Operators steer the agent by passing override flags or by editing `.burp-intel/programs/<slug>.json` per-engagement policy.

### Ghostwriter reporting hub

Ghostwriter is the central reporting/oplog hub both lanes forward into. It is a Docker stack; Praetor ships an auto-setup:

```bash
./setup-ghostwriter.sh     # clones + installs Ghostwriter, wires .env (GHOSTWRITER_*)
```

This downloads several GB of images and binds TCP 443 (skip in `setup.sh` with `PRAETOR_SKIP_GHOSTWRITER=1`). Afterward, open **https://127.0.0.1** (accept the self-signed cert), log in as `admin` (`cd ~/Ghostwriter && ./ghostwriter-cli-linux config get ADMIN_PASSWORD`), create a Project + its Oplog, and set `GHOSTWRITER_OPLOG_ID`. Verify with `ghostwriter_status`, then `sync_to_ghostwriter('<domain>')`. Praetor works fully without Ghostwriter — local `.burp-intel/` stores stay the source of truth.

## Tool Surface

The MCP server exposes tools across the following groups. Architecture detail and per-tool notes are in [CLAUDE.md](CLAUDE.md).

| Group | Examples |
|---|---|
| Scope & configuration | `configure_scope`, `check_scope`, `get_scope` |
| Read | `get_proxy_history`, `get_proxy_count`, `get_sitemap`, `get_scanner_findings`, `get_websocket_history` |
| Analyze | `smart_analyze`, `find_injection_points`, `extract_js_secrets`, `analyze_dom` |
| Send (through Burp) | `curl_request`, `send_raw_request`, `concurrent_requests`, `send_to_repeater` |
| Browser | `browser_crawl`, `browser_navigate`, `browser_click`, `browser_execute_js` |
| Session | `create_session`, `session_request`, `extract_token`, `run_flow` |
| Adaptive scan | `discover_attack_surface`, `auto_probe`, `quick_scan`, `full_recon` |
| Precision attack | `test_auth_matrix`, `test_race_condition`, `fuzz_parameter`, `test_parameter_pollution` |
| Vuln-class natives | `test_csrf`, `test_ssrf`, `test_ssti` (SSTImap-style multi-phase), `test_xxe`, `test_websocket` (CSWSH), `test_prototype_pollution` |
| Auth attack | `forge_jwt`, `crack_jwt_secret`, `test_login_bypass`, `test_mfa_bypass`, `test_session_lifecycle`, `analyze_reset_tokens`, `test_auth_matrix`, `compare_auth_states` |
| Edge cases | `test_cors`, `test_jwt`, `test_graphql`, `test_cloud_metadata`, `test_open_redirect` |
| Advanced | `test_host_header`, `test_request_smuggling`, `test_mass_assignment`, `test_business_logic` |
| Extract | `extract_regex`, `extract_json_path`, `extract_css_selector`, `extract_headers` |
| Repeater & macros | `send_to_repeater_tracked`, `repeater_resend`, `create_macro`, `run_macro` |
| Recon (third-party) | `run_subfinder`, `run_nuclei`, `run_katana`, `run_sqlmap`, `run_dalfox`, `run_ffuf`, `query_crtsh`, `analyze_dns`, `fetch_wayback_urls` |
| Subdomain takeover | `test_subdomain_takeover` — 129 vendor fingerprints (W8 nuclei merge) + DNS-only signal mode (W9: ElasticBeanstalk regional, Azure trafficmanager / azureedge / redis.cache.windows.net). DNS-only entries flag takeover when CNAME resolves but target hostname has no A record (skip body fingerprint match). See `.claude/skills/recon-takeover.md`. |
| Collaborator | `generate_collaborator_payload`, `auto_collaborator_test`, `get_collaborator_interactions` |
| Intel | `save_target_intel`, `load_target_intel`, `lookup_cross_target_patterns`, `set_program_policy` |
| Hunt advisor | `get_hunt_plan`, `get_next_action`, `assess_finding`, `pick_tool` |
| Security research | `research_attack_vector` (curated deep-dive prompts + HackerOne hacktivity + writeup-hub URLs to WebFetch — operationalizes Rule 27's 20% creative-hunting budget) |
| Reporting | `save_finding`, `generate_report`, `format_finding_for_platform`, `export_report` |
| **Network recon (lane)** | `run_network_recon` (chained discover→enum→leads pipeline), `run_nmap`, `get_network_inventory` |
| **Network / AD / post-ex** | `run_network_tool` (sanctioned impacket / netexec / responder / bloodhound-python / certipy / kerbrute / enum4linux-ng / smbmap / evil-winrm / rpcclient / ldapsearch) |
| **Credential loop** | `crack_hashes` (offline hashcat/john), `record_credential`, `list_credentials` |
| **Operator log / evidence** | `record_redteam_action`, `record_loot`, `get_operator_log` (timeline / attack / loot) |
| **Red-team knowledge** | `lookup_gtfobins`, `lookup_lolbas`, `redteam_tool_guide` |
| **Ghostwriter hub** | `ghostwriter_status`, `sync_to_ghostwriter` |

## MCP Prompts

The server publishes ready-to-run workflow templates. Surface them in your client (`/mcp` listing or the prompt picker) and pass arguments to launch a phase.

| Prompt | Args | Purpose |
|---|---|---|
| `hunt-target` | `target` | Standard hunt loop: scope → recon → probe → verify → save. |
| `verify-finding` | `vuln_type`, `endpoint`, `evidence` | Walk a suspected finding through the 7-Question Gate before saving. |
| `triage-program` | `program` | Set per-program policy, scope, and override defaults at engagement start. |
| `chain-findings` | `domain` | Walk saved findings and propose chains that lift NEVER-SUBMIT items into impact. |
| `save-finding-checklist` | `vuln_type`, `endpoint` | Pre-save checklist enforcing replay → assess → save. |

## MCP Resources

Read-only context the agent can attach without spending tool budget. URIs:

| URI | Returns |
|---|---|
| `burp://rules/hunting` | The 28 always-active hunting rules (HARD/DEFAULT/ADVISORY). |
| `burp://rules/engineering` | The 4 engineering rules. |
| `burp://skills/{name}` | One skill markdown file by stem (`hunt`, `verify-finding`, `chain-findings`, …). |
| `burp://knowledge/index` | List of all knowledge categories with context counts. |
| `burp://knowledge/{category}` | Raw JSON for one category (probes + matchers + craft guidance). |
| `burp://intel/{domain}/{kind}` | Saved target intel: `profile`, `endpoints`, `coverage`, `findings`, `fingerprint`, `patterns`, `notes`. |
| `burp://findings/{domain}` | Findings JSON for one domain (alias of `burp://intel/{domain}/findings`). |

## Knowledge Base

The adaptive scan engine reads JSON files from `mcp-server/src/burpsuite_mcp/knowledge/`. Each file declares contexts, server-side matchers, and optional craft guidance for dynamic payload generation. Add a new `.json` file to extend coverage; `auto_probe` picks it up at runtime. The full per-category breakdown lives in [`mcp-server/src/burpsuite_mcp/knowledge/_INDEX.md`](mcp-server/src/burpsuite_mcp/knowledge/_INDEX.md).

### Coverage

| Framework | Status |
|---|---|
| OWASP Web Top 10 (2021) | All 10 categories |
| OWASP API Security Top 10 (2023) | All 10 categories |
| OWASP LLM Top 10 (2025) | 9 / 10 (LLM09 misinformation out-of-scope for active testing) |
| OWASP Mobile Top 10 (2024) | Application surface covered (deep-link, WebView, mobile API, payments). M5 insecure comms handled by the `mobile-dynamic-agent` Frida pinning bypass; M7 binary protections out-of-scope. |
| OWASP WSTG (Web Security Testing Guide) | All sections — information gathering, configuration, identity, authentication, authorization, session, input validation, error handling, cryptography, business logic, client-side, API |
| PayloadsAllTheThings | Every named injection / abuse class mapped, including ZIP Slip, argument injection, GraphQL engine-specific |
| HackTricks Web | Path traversal, SSRF, SSTI, deserialization, prototype pollution, request smuggling, cache poisoning, CSPP, OAuth, SAML, WebDAV, file upload |
| HackTricks Cloud | Anonymous external surface covered: object storage misconfig (S3 / GCS / Azure Blob / R2 / B2 / Spaces / OCI / MinIO), function URLs (Lambda / Cloud Run / Cloud Functions / Azure / OpenFaaS), API gateway (AWS / GCP / Azure APIM / Kong / KrakenD / Tyk), Kubernetes (kubelet / kube-apiserver / etcd / dashboard / ArgoCD / Tekton / Rancher / Portainer / registries). Credential-based privesc (Pacu class) out-of-scope per operator policy. |

Latest additions cover the gap surface most bug-bounty and red-team work hits in 2024–2026: cloud storage anonymous enumeration, serverless function URL discovery, K8s external exposure, mobile deep-link and WebView injection, archive extraction (Zip Slip) and argument injection (`curl --upload-file`, `git ext::`, `ssh -oProxyCommand`, …), GraphQL engine-specific attacks (Hasura admin-secret, Apollo APQ poisoning, federation `_entities` abuse, PostGraphile RLS bypass, Dgraph admin, Strawberry SDL leak), and a perimeter-appliance CVE pack (Citrix NetScaler, F5 BIG-IP, Ivanti Connect Secure, PAN-OS GlobalProtect, MOVEit, SonicWall SSLVPN, CrushFTP, Exchange, Confluence, TeamCity, GeoServer, Log4Shell).

### Scope & Non-Goals

Praetor is a **two-lane pentest & red-team harness**: web / API / cloud / LLM DAST through Burp, **and** network recon + Active Directory / post-exploitation on the network lane. Both lanes are first-class — the tooling, evidence model, and reporting pipeline serve both. Internal-network / AD is **in scope** (this changed in the network-lane release): `run_network_recon`, impacket, netexec, responder, bloodhound-python, certipy, kerbrute, offline cracking, and the credential-reuse loop are all core.

The following remain **out of scope by design**, not gaps to be filled:

- **Binary / memory-corruption exploitation** — no ROP/pwntools/gdb/kernel/V8 exploit development. Praetor operates at the network/service and web layers, not on native-binary crash-to-exploit (e.g. ExploitGym-class tasks).
- **Thick-client / native desktop binaries** — Electron IPC/ASAR inspection ships as reference KB (`desktop_electron`) + skill only; no binary-instrumentation automation for native Windows/macOS apps.
- **Non-HTTP protocol / binary fuzzing** — fuzzing is HTTP/parameter-oriented; no boofuzz/AFL-class grammar or network-protocol fuzzing.
- **Email-infrastructure security** — DNS analysis notes SPF/DMARC *presence* only; no DKIM-selector enumeration, SMTP/STARTTLS/open-relay, or BEC/spoofing assessment.
- **Container-runtime / eBPF behavioral detection** — image scanning (Trivy/Grype/Hadolint) is covered; runtime (Falco-class) is not.
- **Online credential brute-force** — dictionary brute of a live service is refused (HARD Rule 6); default/known-cred checks, single-password spray, and **offline** cracking are in scope.
- **Autonomous destructive actions** — RCE is detection-gated; destructive/brute tool args are refused in both engagement modes. Praetor proves impact with benign markers, never with data destruction (Rules 5–8).

## Save-Finding Pipeline

Three phases enforced by the gate:

1. **Replay.** `resend_with_modification(index)` confirms the anomaly and records a `logger_index`.
2. **Assess.** `assess_finding(...)` runs the 7-question gate (scope, reproducibility, impact, dedup, evidence, NEVER-SUBMIT, triager) and returns `REPORT` / `NEEDS MORE EVIDENCE` / `DO NOT REPORT` plus a suggested confidence.
3. **Save.** `save_finding(...)` persists if the gate passed. The Java extension hard-rejects calls without resolvable evidence, NEVER-SUBMIT classes without `chain_with[]`, and timing/blind classes without `reproductions[]`.

Operators can override individual gate questions with `overrides=["q5_evidence:<reason>", ...]` (audit-trailed), pass `human_verified=True`, or change engagement policy with `set_program_policy`. See `.claude/skills/user-override.md`.

## Skills

Behavioral skills live in `.claude/skills/`:

- `hunt.md` — systematic vulnerability hunting workflow
- `verify-finding.md` — per-class evidence bars and the 7-question gate
- `resume.md` — continue from a previous session, re-verify findings
- `chain-findings.md` — escalate low findings into chained impact
- `report-templates.md` — platform-specific report formatting
- `autopilot.md` — autonomous hunt loop with circuit breaker
- `dispatch-agents.md` — parallel agent orchestration
- `burp-workflow.md`, `investigate.md`, `craft-payload.md`, `static-dynamic-analysis.md`
- `user-override.md` — operator override surfaces when defaults block legitimate findings
- `operational-discipline.md` — cross-role discipline (pentester / BBH / red team / researcher): read before you send, replay before save, annotate live, stop when impact is proved, honour the noise budget
- `security-research.md` — deep-dive an interesting anomaly via `research_attack_vector` + WebFetch on disclosed reports / writeups; operationalizes Rule 27's 20% creative-hunting budget

Always-active rules in `.claude/rules/`:

- `engineering.md` — engineering rules (think first, simplicity, surgical changes, goal-driven execution)
- `hunting.md` — tiered hunting rules (HARD 1-10 tool-enforced, DEFAULT 11-21 overridable, ADVISORY 22-28 on-demand)

## Agents

Project subagents in `.claude/agents/`, auto-loaded by Claude Code at session start. One orchestrator plus specialised workers:

- `grow-agent` — session orchestrator, one domain per run
- `recon-agent` — attack-surface mapping
- `js-analyst` — JS secrets and DOM source→sink flows
- `vuln-scanner` — vulnerability probing, one category per instance
- `finding-verifier` — re-verification with per-class evidence bars
- `payload-crafter` — WAF and filter bypass
- `auth-tester` — authz matrix, IDOR/BFLA, JWT
- `browser-agent` — SPA and JS-heavy targets
- `auth-payment-agent` — OAuth, FIDO2/passkeys, Apple/Google/Samsung Pay, IAP, 3DS
- `fuzz-agent` — tech-aware wordlist generation and ffuf
- `mobile-dynamic-agent` — Frida and adb (pinning bypass, runtime hooks, deep-link sinks)

Roles and parallelization patterns: [AGENTS.md](AGENTS.md).

## Supported Platforms

- Linux
- macOS
- Windows (use `.venv\Scripts\python.exe` in `.mcp.json`)
- WSL (Burp on the Windows host — prefer mirrored networking; NAT fallback available. See [WSL](#wsl-burp-on-the-windows-host))

The Java extension and Python server use platform-independent libraries.

## Contributing

Issues and pull requests welcome. Please:

- Open an issue for non-trivial changes before sending a PR.
- Run the full Python test suite (`cd mcp-server && uv run python -m unittest discover -s tests -v`) and `cd burp-extension && mvn package` before submitting.
- Match the existing style (Java: camelCase methods, snake_case JSON keys; Python: PEP 8, async tools).
- Do not add external Java dependencies; the extension uses only the Montoya API and JDK.

## License

[Apache License 2.0](LICENSE).

This project integrates with Burp Suite (a product of PortSwigger Ltd) and is not affiliated with or endorsed by PortSwigger.
