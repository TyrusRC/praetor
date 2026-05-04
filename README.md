# burpsuite-swiss-knife-mcp

[![MCP Badge](https://lobehub.com/badge/mcp/tyrusrc-burpsuite-swiss-knife-mcp)](https://lobehub.com/mcp/tyrusrc-burpsuite-swiss-knife-mcp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-blue)](https://github.com/TyrusRC/burpsuite-swiss-knife-mcp/releases)
[![Java](https://img.shields.io/badge/java-21%2B-blue)](https://adoptium.net/temurin/releases/?version=21)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio-blue)](https://modelcontextprotocol.io/)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows%20%7C%20wsl-blue)](#supported-platforms)

A Model Context Protocol (MCP) server that connects an LLM client to Burp Suite. The server exposes Burp's HTTP capabilities, scanner, sitemap, proxy history, Collaborator, and a knowledge-driven scan engine to a coding agent so the agent can run authorized penetration tests through Burp.

## Authorized Use

This is an offensive security tool. Use only on systems where you have explicit written permission to test (bug bounty scope, signed penetration test, red team contract, internal lab). The authors are not responsible for misuse.

## Architecture

```
LLM client  <- stdio MCP -> Python MCP server  <- HTTP -> Java Burp extension  <- Montoya API -> Burp Suite
```

- The Java extension exposes a REST API on `127.0.0.1:8111` and tunnels HTTP traffic through Burp's proxy listener (`127.0.0.1:8080`) so all probes appear in Proxy history.
- The Python MCP server is a thin client that the LLM speaks to via stdio.
- Target intelligence is persisted to `.burp-intel/<domain>/` (gitignored).

## Features

- HTTP send tools that route through Burp's proxy (curl-style, raw, repeater, intruder, concurrent).
- Adaptive scan engine driven by a JSON knowledge base (matchers + craft guidance).
- Save-finding pipeline with a 7-question gate (`assess_finding`) and per-program policy overrides.
- Stealth headless browser (Playwright Chromium) that proxies through Burp.
- External recon integrations (subfinder, nuclei, katana) routed via Burp.
- Persistent target memory with staleness detection and cross-target pattern reuse.
- Operator override surfaces for severity, scope filter, NEVER-SUBMIT class, confidence floor.

## Requirements

- Burp Suite Professional or Community Edition
- Java 21+
- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- An MCP-aware LLM client (Claude Code, Claude Desktop, etc.)

Optional:

- Go (for `subfinder`, `nuclei`, `katana`)
- Burp Professional for scanner control and Collaborator

## Installation

Pick the level of automation you want.

### Quick — `uvx` (no clone needed for the MCP server)

The MCP server runs straight from the source tree with `uvx`. You still need the Burp extension JAR loaded in Burp Suite — see the Manual section below for that part.

```sh
uvx --from "git+https://github.com/TyrusRC/burpsuite-swiss-knife-mcp.git#subdirectory=mcp-server" \
    burpsuite-swiss-knife-mcp
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/TyrusRC/burpsuite-swiss-knife-mcp.git#subdirectory=mcp-server",
        "burpsuite-swiss-knife-mcp"
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

The script installs Java 21+, Maven, Python 3.11+, uv, Go, and Playwright Chromium where missing, builds the extension, installs the MCP server, optionally installs ProjectDiscovery tools, and writes `.mcp.json`.

Run `./doctor.sh` afterwards to verify the install.

### Manual

```sh
# 1. Build the Burp extension
cd burp-extension
mvn package
# Load target/burpsuite-swiss-knife-0.3.0.jar in Burp: Extensions -> Add -> Java

# 2. Install the MCP server
cd ../mcp-server
uv venv
uv sync

# 3. Configure your MCP client (see below)
```

### `pipx`

```sh
pipx install "git+https://github.com/TyrusRC/burpsuite-swiss-knife-mcp.git#subdirectory=mcp-server"
burpsuite-swiss-knife-mcp     # entrypoint
```

## Configuration

Create `.mcp.json` in the project root. The file is gitignored; each developer maintains their own.

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "/absolute/path/to/burpsuite-swiss-knife-mcp/mcp-server/.venv/bin/python",
      "args": ["-m", "burpsuite_mcp"]
    }
  }
}
```

On Windows replace the command with `C:\\...\\.venv\\Scripts\\python.exe`. On WSL with Burp on the Windows host, add an `env` block setting `BURP_API_HOST` to the Windows host IP and bind the extension to `0.0.0.0` in the Swiss Knife config tab.

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `BURP_API_HOST` | `127.0.0.1` | Burp extension API host |
| `BURP_API_PORT` | `8111` | Burp extension API port |
| `BURP_API_TIMEOUT` | `30` | HTTP timeout in seconds |
| `BURP_PROXY_HOST` | `127.0.0.1` | Burp proxy listener host |
| `BURP_PROXY_PORT` | `8080` | Burp proxy listener port |

The Java extension also accepts JVM system properties `swissknife.proxy.host` and `swissknife.proxy.port` (highest precedence).

## Usage

Once `.mcp.json` is loaded by your MCP client, the tools are available to the agent. A typical session:

1. `configure_scope` to set include/exclude patterns and auto-filter tracker domains.
2. `browser_crawl` or `discover_attack_surface` to map the target.
3. `auto_probe` to run knowledge-driven probes on parameters.
4. `assess_finding` followed by `save_finding` for each suspected issue.
5. `generate_report` to export findings.

The agent receives expert methodology through the skill files in `.claude/skills/`. Operators steer the agent by passing override flags or by editing `.burp-intel/programs/<slug>.json` per-engagement policy.

## Tool Surface

The MCP server exposes tools across the following groups. Architecture detail and per-tool notes are in [CLAUDE.md](CLAUDE.md).

| Group | Examples |
|---|---|
| Scope & configuration | `configure_scope`, `check_scope`, `get_scope` |
| Read | `get_proxy_history`, `get_sitemap`, `get_scanner_findings`, `get_websocket_history` |
| Analyze | `smart_analyze`, `find_injection_points`, `extract_js_secrets`, `analyze_dom` |
| Send (through Burp) | `curl_request`, `send_raw_request`, `concurrent_requests`, `send_to_repeater` |
| Browser | `browser_crawl`, `browser_navigate`, `browser_click`, `browser_execute_js` |
| Session | `create_session`, `session_request`, `extract_token`, `run_flow` |
| Adaptive scan | `discover_attack_surface`, `auto_probe`, `quick_scan`, `bulk_test`, `full_recon` |
| Precision attack | `test_auth_matrix`, `test_race_condition`, `fuzz_parameter`, `test_parameter_pollution` |
| Edge cases | `test_cors`, `test_jwt`, `test_graphql`, `test_cloud_metadata`, `test_open_redirect` |
| Advanced | `test_host_header`, `test_request_smuggling`, `test_mass_assignment`, `test_business_logic` |
| Extract | `extract_regex`, `extract_json_path`, `extract_css_selector`, `extract_headers` |
| Repeater & macros | `send_to_repeater_tracked`, `repeater_resend`, `create_macro`, `run_macro` |
| Recon | `query_crtsh`, `analyze_dns`, `run_subfinder`, `run_nuclei`, `run_katana` |
| Collaborator | `generate_collaborator_payload`, `auto_collaborator_test`, `get_collaborator_interactions` |
| Intel | `save_target_intel`, `load_target_intel`, `lookup_cross_target_patterns`, `set_program_policy` |
| Hunt advisor | `get_hunt_plan`, `get_next_action`, `assess_finding`, `pick_tool` |
| Reporting | `save_finding`, `generate_report`, `format_finding_for_platform`, `export_report` |

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

The adaptive scan engine reads JSON files from `mcp-server/src/burpsuite_mcp/knowledge/`. Each file declares contexts, server-side matchers, and optional craft guidance for dynamic payload generation. Categories cover injection, authentication, authorization, client-side, business logic, infrastructure, file handling, deserialization, and emerging vectors (LLM prompt injection, OAuth device flow, webhook replay, DOM clobbering, CSS prototype pollution, HTTP/3 QUIC). Add a new `.json` file to extend coverage; `auto_probe` picks it up at runtime.

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

Always-active rules in `.claude/rules/`:

- `engineering.md` — engineering rules (think first, simplicity, surgical changes, goal-driven execution)
- `hunting.md` — tiered hunting rules (HARD 1-10 tool-enforced, DEFAULT 11-21 overridable, ADVISORY 22-28 on-demand)

## Supported Platforms

- Linux
- macOS
- Windows (use `.venv\Scripts\python.exe` in `.mcp.json`)
- WSL (set `BURP_API_HOST` to the Windows host IP and bind the extension to `0.0.0.0`)

The Java extension and Python server use platform-independent libraries.

## Contributing

Issues and pull requests welcome. Please:

- Open an issue for non-trivial changes before sending a PR.
- Run `cd mcp-server && uv run python -m unittest tests.test_assess_finding -v` and `cd burp-extension && mvn package` before submitting.
- Match the existing style (Java: camelCase methods, snake_case JSON keys; Python: PEP 8, async tools).
- Do not add external Java dependencies; the extension uses only the Montoya API and JDK.

## License

[Apache License 2.0](LICENSE).

This project integrates with Burp Suite (a product of PortSwigger Ltd) and is not affiliated with or endorsed by PortSwigger.
