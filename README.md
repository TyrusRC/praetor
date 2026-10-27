# Praetor

*Agentic pentest & red-team harness — web (Burp) + network/AD, one operator log.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Java](https://img.shields.io/badge/java-21%2B-blue)](https://adoptium.net/temurin/releases/?version=21)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio-blue)](https://modelcontextprotocol.io/)

Praetor is an MCP server that turns Claude Code (or any MCP client) into an agentic pentester and red-teamer. Two co-equal lanes share one evidence model, one save-finding pipeline, and one operator log:

- **Web lane** — Burp Suite as the execution engine. Knowledge-driven probe engine, native vuln-class orchestrators, an exploit confirm→escalate pipeline, browser automation, and [vigil](https://github.com/TyrusRC/vigil) as the default DAST scanner. Every request routes through Burp.
- **Network lane** — nmap, impacket, netexec, responder, BloodHound, certipy, and offline cracking. MITRE ATT&CK–tagged operator log with loot chain-of-custody.

Supporter lanes (mobile, cloud, LLM/MCP security) plug into the same model. Both lanes forward into [Ghostwriter](https://github.com/GhostManager/Ghostwriter) as an optional reporting hub.

## Quick Start

```sh
git clone https://github.com/TyrusRC/praetor.git && cd praetor
./setup.sh                # builds extension, installs server, writes .mcp.json
./doctor.sh               # verify
```

Load `target/praetor-burp-ext-*.jar` in Burp (*Extensions → Add → Java*), reload your MCP client, and run `check_pro_features()` to confirm the link.

## Architecture

```
                                    ┌─ web lane ──────> Java Burp extension (127.0.0.1:8111)
LLM client <- stdio MCP -> server ─┤─ non-HTTP lane ─> burp-expedition extension (:18112)
                                    └─ network lane ──> nmap / impacket / netexec / ...
                        all lanes ─> Ghostwriter (optional) · Haruspex decision engine (optional)
```

- **Web lane:** REST API on `:8111`, HTTP tunneled through Burp's proxy (`:8080`). Every probe appears in Proxy history with a Logger index.
- **Non-HTTP lane:** [burp-expedition](https://github.com/TyrusRC/burp-expedition) — TCP/UDP proxy with per-protocol dissectors (Redis, PostgreSQL, MySQL, MongoDB, MQTT, Modbus, DNP3, DNS, WebSocket, Protobuf, HTTP/2, STUN, QUIC). Intercept, replay, fuzz, match-replace on raw wire protocols.
- **Network lane:** tools run directly; each action is ATT&CK-tagged in the operator log.
- **[Haruspex](https://github.com/TyrusRC/haruspex):** optional local decision model for probe ranking and finding enrichment. Falls back to deterministic ordering when off.

## Features

**Scan & Probe**
- Adaptive scan engine driven by a JSON knowledge base mapped to OWASP Top 10, WSTG, API Top 10, HackTricks, PayloadsAllTheThings, and Nuclei template categories
- Default scan pipeline: [vigil](https://github.com/TyrusRC/vigil) (web DAST) + [groma](https://github.com/TyrusRC/groma) (network) run first, then targeted probing on leads
- Native vuln-class orchestrators: CSRF, SSRF, SSTI (multi-phase), XXE, WebSocket (upgrade + message injection), prototype pollution, padding oracle, CRLF, cache poisoning, clickjacking, DOM sinks
- API schema auto-fuzz: walk every OpenAPI/Swagger endpoint with type-aware injection payloads
- Passive proxy analysis: scan captured traffic for info leaks without sending requests
- Impact-first severity: confirmed exploit + real attack path + environment context drives the rating, not just the vuln class name

**Exploit Pipeline (detect → confirm → escalate)**
- `confirm_*` tools prove injection exists (SQLi, RCE, SSRF, SSTI, XXE, XSS, NoSQL, LDAP, XPath, XSLT, SSI, expression injection, email injection, second-order, cache deception, IDOR, race condition)
- `escalate_*` tools prove attacker capability (SSTI→RCE, SQLi→file read/OS cmd, SSRF→IMDS creds, XXE→OOB exfil, LFI→sensitive files, IDOR→cross-account, prototype pollution→gadget RCE, open redirect→token theft)

**Auth & Session**
- JWT forge (8 modes) + secret cracking, login bypass, MFA bypass, session lifecycle, reset-token entropy
- OAuth/OIDC/SAML/passkey protocol simulators
- Auth matrix testing across roles

**Network & Red Team**
- Default scan pipeline: groma (full port range + CVE checks) → nmap (service enum + NSE) → auto-loot → web-lane bridge
- Sanctioned runner for impacket, netexec, responder, BloodHound, certipy, kerbrute, evil-winrm
- Credential capture → offline crack → store → reuse loop
- BloodHound/certipy ingestion into ATT&CK-tagged operator log
- Non-HTTP protocol testing via burp-expedition: relay, intercept, fuzz, repeat for TCP/UDP services

**Browser & Recon**
- Stealth headless browser (CloakBrowser) routed through Burp
- Third-party tool wrappers: subfinder, httpx, katana, amass, ffuf, sqlmap, dalfox, nikto, and more
- JS secret extraction, DOM sink analysis, tech stack fingerprinting

**Reporting & Evidence**
- 7-question save-finding gate with per-program policy overrides
- CVSS 4.0 scoring (environment-aware, exposure-adjusted)
- GUI screenshot capture with automatic secret redaction
- Reports: pentest, red-team, compliance (PCI-DSS, SOC2, HIPAA, GDPR, OWASP)
- Export: SARIF, JUnit XML, HTML engagement graph, platform-specific (HackerOne, Bugcrowd)
- Engagement narrative graph (goal→intent→fact→finding→asset) with interactive HTML viewer

**Protocol & Transport**
- HTTP/2 attacks: CL desync smuggling, HPACK bomb, rapid reset (CVE-2023-44487), CONTINUATION flood (CVE-2024-27983), h2c upgrade bypass
- WebRTC/STUN/TURN: open relay detection, STUN binding, ICE candidate IP leak from SDP
- QUIC: version probe and Initial packet fingerprinting (SNI/ALPN extraction)
- Built-in OOB callback server for blind testing without Burp Collaborator
- Reverse proxy bypass: Nginx off-by-slash, X-Original-URL, path normalization, DAV heap overflow

**Additional Lanes**
- **Mobile:** Frida + adb dynamic testing, APK decompile, deep-link and WebView abuse. Full MASTG via [centurion](https://github.com/TyrusRC/centurion)
- **Cloud:** prowler, scout-suite, pacu, IaC scanning, container/K8s security
- **LLM/MCP:** prompt injection, tool poisoning, system-prompt leakage, OWASP LLM/AI Top 10
- **Fuzzing:** structure-aware file upload fuzzing, AFL integration, crash triage, TCP/UDP protocol fuzzing via expedition

**Safety**
- HARD tool-layer blocks on destructive payloads (non-overridable)
- Confirm-before-dangerous on state-changing actions
- Engagement modes: operator (audit-log + proceed) or strict (hard block)
- Benign-PoC standard: reaching the sink proves impact without causing harm

## Installation

### One-line (no clone)

```sh
# Claude Code
claude mcp add praetor -- uvx --from \
  "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server" praetor-mcp
```

### Full local checkout

```sh
./setup.sh        # Linux / macOS
./setup.ps1       # Windows
```

The script builds the Burp extension, installs the MCP server, clones burp-expedition, and writes `.mcp.json`.

### Manual

```sh
cd burp-extension && mvn package          # build extension jar
cd ../mcp-server && uv venv && uv sync    # install MCP server
```

### MCP client config

```json
{
  "mcpServers": {
    "praetor": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/TyrusRC/praetor.git#subdirectory=mcp-server", "praetor-mcp"],
      "env": { "BURP_API_HOST": "127.0.0.1", "BURP_API_PORT": "8111" }
    }
  }
}
```

Works with Claude Code, Codex, Gemini CLI, Cursor, Windsurf, Antigravity, DeepSeek Harness, and any MCP-aware client. Per-host config examples in [`examples/mcp-clients/`](examples/mcp-clients/).

## Usage

### Commands (Claude Code)

- **`/checklist <domain>`** — coverage-driven pentest (OWASP/WSTG checklist → hunt → report)
- **`/exploit <target> [objective]`** — objective-driven red-team (quick wins → exploit → attack-path map)

### Web lane

```
configure_scope → run_vigil (automated DAST) → browser_crawl → auto_probe → assess_finding → save_finding → generate_report
```

### Network lane

```
run_groma (full port scan + CVE) → run_network_recon (service enum) → crack_hashes → run_network_tool (lateral) → sync_to_ghostwriter
```

### Non-HTTP protocols

```
tcp_proxy_add_listener → (client traffic) → tcp_proxy_messages → tcp_repeat / tcp_fuzz → save_finding
```

## Configuration

### WSL (Burp on Windows)

**Mirrored mode (recommended):** Add `networkingMode=mirrored` to `%UserProfile%\.wslconfig`, restart WSL. Burp on `127.0.0.1:8111` is reachable from WSL with no changes.

**NAT mode:** Set `BURP_API_HOST` to the Windows host IP, bind the extension to `0.0.0.0` with `-Dpraetor.allow_non_loopback_bind=true`.

### Environment variables

All optional. The core hunt loop runs with no keys.

| Variable | Default | Purpose |
|---|---|---|
| `BURP_API_HOST` / `PORT` | `127.0.0.1` / `8111` | Burp extension API |
| `BURP_PROXY_HOST` / `PORT` | `127.0.0.1` / `8080` | Burp proxy listener |
| `PRAETOR_LLM_PROVIDER` | — | LLM for analysis tools (openai/anthropic/ollama/gemini/deepseek/...) |
| `PRAETOR_LLM_API_KEY` | — | LLM key (or use provider-native vars) |
| `PRAETOR_DECISION_PROVIDER` | auto | Decision engine: jev / llm / off |
| `GHOSTWRITER_URL` | — | Ghostwriter base URL (optional) |
| `PRAETOR_PROFILE` | all | Tool lanes to advertise (web/network/mobile/cloud/core/codex) |

Full list with OSINT keys, Ghostwriter auth, and CI options in `.env.example`.

### Decision engine

Three backends (auto-selected, best first): local [Haruspex](https://github.com/TyrusRC/haruspex) model, any `PRAETOR_LLM_*` provider (including local Ollama), or off (deterministic ordering). The engine orders probes and enriches verdicts — it never drops coverage.

## Knowledge Base

JSON files under `mcp-server/src/praetor/knowledge/`. Each file declares contexts, server-side matchers, and craft guidance. `auto_probe` loads them at runtime.

**Coverage:** OWASP Web Top 10, API Top 10, LLM Top 10, Mobile Top 10, WSTG, ASVS 5.0, AISVS 1.0, MASVS v2, PayloadsAllTheThings, HackTricks Web + Cloud, plus recent CVEs (React2Shell, PHP2Shell, Brotli RCE, Squidbleed, wp2shell, nginx DAV, SonicWall SMA, Collabora cmdi, SharePoint RCE). Index at [`_INDEX.md`](mcp-server/src/praetor/knowledge/_INDEX.md).

## Save-Finding Pipeline

```
replay (≥3× for blind)  →  assess_finding (7-question gate)  →  save_finding (persist + dedup)
```

Gates: scope, reproducibility, impact, dedup, evidence, never-submit class, triager check. Severity is impact-first: confirmed exploit unlocks the class ceiling, unconfirmed caps at MEDIUM, scanner-only caps at LOW, staging caps at MEDIUM. Missing context (environment, exposure, business type) is flagged explicitly — the agent asks the operator instead of assuming. Operators override with `overrides=[...]` or per-program policy.

## Agents

Two commanders (Opus-tier, strategic), one per-domain orchestrator, and specialized workers (recon, vuln-scanner, finding-verifier, payload-crafter, auth-tester, browser, mobile, network, cloud, LLM, and more). Full roster in [AGENTS.md](AGENTS.md).

## Cross-Host Support

Everything Claude Code auto-loads from disk is also exposed as MCP tools: `praetor_bootstrap()`, `get_rules()`, `list_skills()`/`get_skill()`, `list_agents()`/`get_agent()`. Non-Claude hosts call `praetor_bootstrap()` first. Per-host rule files ship for Claude Code, Codex, Gemini CLI, Cursor, and Windsurf.

For eager-loading hosts (Codex, dsh), set `PRAETOR_PROFILE` to advertise a smaller tool set. Gated tools stay runnable via `run_tool()`.

## Burp Edition Compatibility

**Professional** — full support.

**Community** — supported with fallbacks. `run_vigil` + `auto_probe` replace the active scanner; `analyze_proxy_passive` replaces passive scan rules; the built-in OOB callback server auto-activates when Collaborator is unavailable; `concurrent_requests` bypasses Intruder throttling. Run `check_pro_features()` at session start.

## Supported Platforms

Linux, macOS, Windows, WSL. The Java extension and Python server use platform-independent libraries.

## Contributing

- Open an issue for non-trivial changes before sending a PR
- Run tests: `cd mcp-server && uv run python -m unittest discover tests` and `cd burp-extension && mvn package`
- Match existing style (Java: camelCase methods, snake_case JSON keys; Python: PEP 8, async tools)
- No external Java dependencies — extension uses only Montoya API and JDK

## License

[Apache License 2.0](LICENSE)
