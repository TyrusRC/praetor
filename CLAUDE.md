# Development Guidelines

This document contains critical information about working with this codebase. Follow these guidelines precisely.

## Project Overview

Burp Suite Swiss Knife MCP — integrates Burp Suite Professional with Claude Code via the Model Context Protocol (MCP). Three-layer architecture:

```
Claude Code (LLM) → Python MCP Server (stdio) → Java Burp Extension (REST API on 127.0.0.1:8111) → Burp Suite (Montoya API)
```

Two codebases in one repo:
- `burp-extension/` — Java 21, Maven, Burp Montoya API
- `mcp-server/` — Python 3.11+, Hatch, FastMCP

## Core Development Rules

1. Package Management
   - **Java:** Maven only (`mvn package`, `mvn clean install`)
   - **Python:** uv (`uv run python -m burpsuite_mcp`) — always use `uv run` instead of python3/pip directly
   - Dependencies in `pom.xml` (Java) and `pyproject.toml` / `requirements.txt` (Python)

2. Build Commands
   - Build extension JAR: `cd burp-extension && mvn package`
   - Output: `burp-extension/target/burpsuite-swiss-knife-0.2.0.jar`
   - Install MCP server: `cd mcp-server && uv pip install -e .`
   - Run MCP server: `uv run python -m burpsuite_mcp`

3. Code Quality
   - **Java:** No external JSON libraries — use `JsonUtil` for all serialization
   - **Python:** Type hints required, async functions for all MCP tools
   - Public APIs must have docstrings
   - Functions must be focused and small
   - Follow existing patterns exactly

4. Zero External Dependencies (Java)
   - The Burp extension intentionally has NO external dependencies beyond Montoya API
   - `JsonUtil` is a custom recursive descent JSON parser/builder — use it, don't add Gson/Jackson
   - HTTP server uses JDK's `com.sun.net.httpserver.HttpServer`
   - NEVER add external JARs to the extension

5. Testing
   - No formal test suite exists yet
   - Manual testing through Burp extension loading and MCP client
   - When tests are added: JUnit 5 for Java, pytest for Python

## Code Style

### Java
- camelCase for methods/variables, PascalCase for classes
- All handlers extend `BaseHandler` and implement `handleRequest(HttpExchange)`
- Use `BaseHandler` helper methods: `getQueryParams()`, `sendJson()`, `getRequestBody()`, `parseJson()`
- Thread safety: use `CopyOnWriteArrayList` or `synchronized` for shared state
- API routes use kebab-case: `/api/analysis/injection-points`
- JSON response keys use snake_case: `"proxy_history"`, `"total_count"`

### Python
- PEP 8 naming (snake_case for functions/variables)
- Class names in PascalCase
- Constants in UPPER_SNAKE_CASE
- All MCP tools are `async def` decorated with `@mcp.tool()`
- Each tool module has a `register(mcp)` function
- Use f-strings for formatting
- Error handling pattern: `if "error" in data: return data["error"]`

## System Architecture

```
burp-extension/src/main/java/com/swissknife/
├── SwissKnifeExtension.java    # Entry point (BurpExtension interface)
├── server/
│   ├── ApiServer.java          # HTTP server, routes, thread pool (6 threads)
│   └── BaseHandler.java        # Abstract handler with CORS, parsing, response helpers
├── handlers/                   # 25 endpoint handlers (one per API domain)
│   ├── HealthHandler.java      # GET /api/health
│   ├── ProxyHandler.java       # GET /api/proxy/history, /api/proxy/history/{index}
│   ├── SitemapHandler.java     # GET /api/sitemap
│   ├── ScopeHandler.java       # GET/POST /api/scope/* — include/exclude/auto-filter
│   ├── ScannerHandler.java     # POST /api/scanner/scan, /crawl; GET /status, /findings, /findings/new; DELETE/POST scan control
│   ├── HttpSendHandler.java    # POST /api/http/send, /raw, /resend, /repeater, /intruder, /curl
│   ├── SessionHandler.java     # POST /api/session/* — persistent sessions, flows, extraction
│   ├── AnalysisHandler.java    # POST /api/analysis/* (routes to analysis modules)
│   ├── FuzzHandler.java        # POST /api/fuzz
│   ├── AttackHandler.java      # POST /api/attack/auth-matrix, /race, /hpp
│   ├── CollaboratorHandler.java # POST /api/collaborator/payload, /auto-test; GET /interactions
│   ├── SearchHandler.java      # POST /api/search/history, /response-diff, /compare, /send-to-comparer
│   ├── NotesHandler.java       # POST/GET /api/notes/findings; GET /api/notes/export
│   ├── CookieHandler.java      # GET /api/cookies
│   ├── WebSocketHandler.java   # GET /api/websocket/history
│   ├── SitemapExportHandler.java # GET /api/export/sitemap
│   ├── ResourceHandler.java    # GET /api/resources; POST /fetch, /fetch-page
│   ├── InterceptHandler.java   # POST /api/intercept/enable, /disable; GET /status
│   ├── MatchReplaceHandler.java # POST /api/match-replace/add, /clear; GET list; DELETE /{id}
│   ├── AnnotationHandler.java  # POST /api/annotations/set, /bulk; GET /{index}
│   ├── TrafficMonitorHandler.java # GET /api/traffic/stats, /live; POST/GET/DELETE monitor/*
│   ├── ExtractTextHandler.java # POST /api/extract-text/regex, /css-selector, /links
│   ├── ExtractDataHandler.java # POST /api/extract-data/json-path, /headers, /hash
│   ├── RepeaterHandler.java    # POST /api/repeater/send, /resend; GET /tabs; DELETE /{name}
│   └── MacroHandler.java       # POST /api/macro/create, /run; GET /list, /{name}; DELETE /{name}
├── analysis/                   # 8 analysis modules
│   ├── ParameterExtractor.java
│   ├── FormExtractor.java
│   ├── EndpointExtractor.java
│   ├── InjectionPointDetector.java
│   ├── TechStackDetector.java
│   ├── JsSecretExtractor.java
│   ├── DomAnalyzer.java
│   └── MatcherEngine.java
├── store/
│   └── FindingsStore.java      # Thread-safe in-memory findings storage
└── util/
    └── JsonUtil.java           # Custom JSON parser/builder (zero dependencies)

mcp-server/src/burpsuite_mcp/
├── __main__.py                 # Entry point → mcp.run(transport="stdio")
├── server.py                   # FastMCP instance + tool registration (27 modules)
├── config.py                   # Env vars: BURP_API_HOST, BURP_API_PORT, BURP_API_TIMEOUT
├── client.py                   # Async HTTP client (httpx) to extension
├── processing/
│   └── formatters.py           # Token-efficient output formatting (ASCII tables)
├── payloads/                   # Curated payload files for get_payloads tool (16 JSON files)
│   ├── xss.json                # XSS payloads by context (angular, dom, svg, waf bypass, etc.)
│   ├── sqli.json               # SQLi payloads by DB engine (mysql, postgres, mssql, blind, etc.)
│   ├── ssti.json               # SSTI payloads by template engine (jinja2, twig, freemarker, etc.)
│   ├── ssrf.json               # SSRF payloads (cloud metadata, DNS rebind, protocol, etc.)
│   ├── command_injection.json
│   ├── path_traversal.json
│   ├── xxe.json
│   ├── auth_bypass.json
│   ├── cors.json
│   ├── csrf.json
│   ├── race_condition.json
│   ├── hpp.json
│   ├── open_redirect.json
│   ├── lfi.json
│   └── file_upload.json
├── knowledge/                  # Knowledge base with server-side matchers for auto_probe (27 JSON files)
│   ├── sqli.json, xss.json, ssti.json, ssrf.json, command_injection.json
│   ├── path_traversal.json, xxe.json, auth_bypass.json, cors.json, csrf.json
│   ├── race_condition.json, hpp.json, idor.json, jwt.json, graphql.json
│   ├── deserialization.json, crlf_injection.json, open_redirect.json
│   ├── mass_assignment.json, request_smuggling.json, llm_injection.json
│   ├── info_disclosure.json, websocket.json, file_upload.json
│   └── tech_vulns.json         # Tech-specific vulnerabilities (reference only, no probes)
└── tools/                      # 141 MCP tools across 29 modules
    ├── read.py                 # Proxy history, sitemap, scanner, scope, cookies, websocket (10 tools)
    ├── analyze.py              # Parameters, forms, endpoints, injection points, tech stack, JS secrets, smart_analyze (8 tools)
    ├── send.py                 # HTTP requests, raw, resend, repeater, intruder, curl (6 tools)
    ├── session.py              # Session CRUD, session_request, extract_token, run_flow (6 tools)
    ├── scope.py                # configure_scope with include/exclude/auto-filter (1 tool)
    ├── testing.py              # Fuzz, auth compare, comparer, diff, auth matrix, race, HPP (7 tools)
    ├── scan.py                 # Adaptive scan: discover_attack_surface, auto_probe, scan_target, quick_scan, probe_endpoint, batch_probe, discover_hidden_parameters, full_recon, bulk_test (9 tools)
    ├── edge.py                 # Edge-case tests: CORS, JWT, GraphQL, cloud metadata, common files, open redirect, LFI, file upload (8 tools)
    ├── correlate.py            # Search, findings correlation, response diff (3 tools)
    ├── collaborate.py          # Collaborator payloads, interactions, auto-test (3 tools)
    ├── scanner.py              # Scan URL, crawl target, scan status (3 tools)
    ├── scanner_control.py      # Cancel scan, pause/resume (status), poll new findings (4 tools)
    ├── notes.py                # Save, get, export findings (3 tools)
    ├── payloads.py             # get_payloads — context-aware payload lookup (1 tool)
    ├── dom.py                  # DOM structure + JS sink/source analysis (1 tool)
    ├── export.py               # Sitemap export as JSON or OpenAPI (1 tool)
    ├── resources.py            # Static resources listing, fetch, fetch-page (3 tools)
    ├── utility.py              # Encode/decode (base64, URL, HTML, hex, JWT, hashes) (1 tool)
    ├── cve.py                  # CVE intelligence: match tech stack, search CVEs (2 tools)
    ├── report.py               # Professional reports: pentest report + platform-specific formatting (2 tools)
    ├── recon.py                # External recon: subfinder, nuclei, katana, probe_hosts, pipeline (6 tools)
    ├── proxy_control.py        # Intercept, match-replace, annotations, stats, live traffic, monitors (15 tools)
    ├── extract.py              # Response extraction: regex, JSON path, CSS selector, headers, links, hash (6 tools)
    ├── transform.py            # Encoding chains, smart decode, encoding detection (3 tools)
    ├── repeater.py             # Tracked Repeater tabs: send, list, resend with mods, remove (4 tools)
    ├── macro.py                # Reusable request macros: create, run, list, get, delete (5 tools)
    ├── intel.py                # Target intelligence: save/load intel, freshness, notes, cross-target (5+ tools)
    ├── browser.py              # Stealth headless Chromium through Burp proxy — crawl, click, fill, interact (10 tools)
    └── advisor.py              # Hunt advisor: pre-computed plans, tool selection, finding validation (5 tools)
```

## Key Design Decisions

- **Localhost only:** API server binds to 127.0.0.1:8111, no external access
- **Session-based architecture:** Persistent attack sessions with auto-updating cookie jar, auth tokens, and variable extraction — Claude crafts requests freely without depending on proxy history
- **Token efficiency:** One smart tool call > five chatty ones. `run_flow` executes multi-step attacks (login → extract CSRF → exploit) in a single call. Formatters produce compact ASCII tables for LLM consumption
- **Building blocks + smart helpers:** Low-level primitives (session, request, extract) for creative attack chaining, plus high-level tools (auth matrix, race condition) where server-side coordination matters
- **Smart scope:** Auto-filters tracker/ad/CDN noise for clean bug bounty testing
- **Payload knowledge:** Curated payloads from HackTricks/PayloadsAllTheThings fill Claude's gaps for advanced/evasive techniques (WAF bypass, framework-specific SSTI, blind injection)
- **Knowledge-driven scanning:** `knowledge/` directory has 24 categories with server-side matchers — `auto_probe` sends probes and validates findings server-side for low false positives. Separate from `payloads/` which is for `get_payloads` tool
- **Precision over spray:** No mass brute force or enumeration — use nuclei/sqlmap/ffuf for that. This tool focuses on intelligent, context-aware vulnerability testing
- **Response truncation:** Responses > 50KB are trimmed (configurable via `BURP_MAX_RESPONSE_SIZE`)
- **In-memory storage:** Sessions and FindingsStore are not persisted — lost on extension reload

## Adding New Features

### Adding a new MCP tool
1. Create or extend a tool module in `mcp-server/src/burpsuite_mcp/tools/`
2. Define an `async def` function with `@mcp.tool()` decorator
3. Register in the module's `register(mcp)` function
4. Import and call `register()` in `server.py`

### Adding a new API endpoint
1. Create a handler class in `burp-extension/src/main/java/com/swissknife/handlers/`
2. Extend `BaseHandler`, implement `handleRequest(HttpExchange exchange)`
3. Register the route in `ApiServer.java` via `server.createContext()`

### Adding a new analysis module
1. Create a class in `burp-extension/src/main/java/com/swissknife/analysis/`
2. Accept request/response data, return structured results via `JsonUtil`
3. Call from the appropriate handler (usually `AnalysisHandler`)

### Adding payloads (for `get_payloads` tool)
1. Edit or create a JSON file in `mcp-server/src/burpsuite_mcp/payloads/`
2. Follow the schema: `{"category": "...", "contexts": {"context_name": {"description": "...", "payloads": [{"payload": "...", "description": "...", "waf_bypass": bool}]}}}`
3. The `get_payloads` tool reads these files directly — no registration needed

### Adding knowledge base probes (for `auto_probe` engine)
1. Edit or create a JSON file in `mcp-server/src/burpsuite_mcp/knowledge/`
2. Must include `"contexts"` with probes and matchers for server-side validation
3. Files listed in `_REFERENCE_ONLY` set in `scan.py` are excluded from auto-probe (e.g., `tech_vulns`)
4. `auto_probe` loads and caches these via `_load_knowledge()` — no registration needed

## Design Spec

Full design spec for new features: `docs/superpowers/specs/2026-04-04-mcp-pentesting-features-design.md`

Implementation phases:
1. **Foundation** — bug fixes, smart scope (`configure_scope`), session management (`create_session`, `session_request`, `extract_token`, `run_flow`)
2. **Attack Tools** — `test_auth_matrix`, `test_race_condition`, `test_parameter_pollution`
3. **Payload Knowledge** — curated JSON payload files + `get_payloads` tool
4. **Polish** — existing tool improvements, updated registrations

## Development Philosophy

- **Simplicity**: Write simple, straightforward code
- **Readability**: Make code easy to understand
- **Performance**: Consider performance without sacrificing readability
- **Maintainability**: Write code that's easy to update
- **Security-First**: This is a security tool — never introduce vulnerabilities
- **Less Code = Less Debt**: Minimize code footprint
- **Build Iteratively**: Start with minimal functionality and verify it works before adding complexity

## Coding Best Practices

- **Early Returns**: Use to avoid nested conditions
- **Descriptive Names**: Use clear variable/function names
- **DRY Code**: Don't repeat yourself
- **Minimal Changes**: Only modify code related to the task at hand
- **TODO Comments**: Mark issues in existing code with "TODO:" prefix
- **Simplicity**: Prioritize simplicity and readability over clever solutions
- **Clean Logic**: Keep core logic clean and push implementation details to the edges
- **Thread Safety**: All shared state in Java must use concurrent collections or synchronization

## Commits and Pull Requests

- For commits fixing bugs or adding features based on user reports add:
  ```bash
  git commit --trailer "Reported-by:<name>"
  ```
- For commits related to a Github issue, add:
  ```bash
  git commit --trailer "Github-Issue:#<number>"
  ```
- NEVER mention a `co-authored-by` or similar aspects. Never mention the tool used to create the commit message or PR.
- Create detailed PR messages focusing on the high-level problem and solution, not code specifics.

## Target Memory System

Persistent target intelligence stored in `.burp-intel/<domain>/` (gitignored, never committed).

### MCP Tools
- `save_target_intel(domain, category, data)` — Write to profile/endpoints/coverage/findings/fingerprint/patterns
- `load_target_intel(domain, category)` — Read stored intel (use `"all"` for summary)
- `check_target_freshness(domain, session)` — Compare page fingerprints to detect changes
- `save_target_notes(domain, notes)` — Save/update human-editable markdown notes
- `lookup_cross_target_patterns(tech_stack, vuln_class)` — Find attack patterns from other targets with overlapping tech

### Data Files
- `profile.json` — Tech stack, auth, scope rules, WAF, security headers grade
- `endpoints.json` — Discovered endpoints with parameters and risk scores
- `coverage.json` — Test coverage with knowledge version tracking
- `findings.json` — Vulnerability findings with states (suspected/confirmed/stale/likely_false_positive)
- `fingerprint.json` — Page hashes for staleness detection
- `patterns.json` — Successful attack patterns indexed by vuln class + tech stack (cross-target learning)
- `notes.md` — Claude observations + user corrections (human-editable)

### Finding States
- `suspected` — Anomaly detected, not yet verified
- `confirmed` — Reproduced with evidence (Collaborator, timing, error-based)
- `stale` — Was confirmed but target changed, needs re-verification
- `likely_false_positive` — 2+ consecutive verification failures

### Design Principles
- Memory is advisory, not authoritative — always verify before trusting
- Staleness detection via page fingerprinting on session start
- Knowledge version tracking — new probes trigger re-testing
- Deduplication — same endpoint + vuln type + param = update, not duplicate

## Bug Bounty Skills

Located in `.claude/skills/`:

- `hunt.md` — Systematic vulnerability hunting with tech-adaptive priorities, JS analysis, severity assessment, and pivot strategies
- `verify-finding.md` — Verify suspected findings with evidence requirements for 17 vuln types, 7-Question Gate, NEVER SUBMIT list
- `resume.md` — Resume testing with attack surface delta detection, stale finding triage, and knowledge re-probing
- `burp-workflow.md` — Efficient Burp Suite tool orchestration — decision trees for picking the right tool
- `investigate.md` — Deep anomaly investigation, filter mapping, finding escalation, and attack chaining
- `craft-payload.md` — Adaptive payload crafting when standard attacks fail — filter probing, encoding bypass chains, incremental testing
- `dispatch-agents.md` — Parallel agent orchestration — dispatch recon/scanner/verifier/crafter agents simultaneously
- `static-dynamic-analysis.md` — JS source analysis, DOM sink/source tracing, behavioral profiling, page change detection, cross-analysis workflows
- `chain-findings.md` — Exploit chain building: escalate low-severity findings via A→B→C chains with escalation table
- `report-templates.md` — Platform-specific report generation for HackerOne, Bugcrowd, Intigriti, Immunefi with CVSS guide
- `autopilot.md` — Autonomous hunt loop with circuit breaker, rate limiting, checkpoint modes, and safety controls

## Always-Active Rules

Located in `.claude/rules/`:

- `hunting.md` — 20 behavioral rules enforced every turn: scope safety, evidence requirements, 7-Question Validation Gate, NEVER SUBMIT list (23+ non-reportable finding types), efficiency guidelines

## Agent Team (AGENTS.md)

Defined in `AGENTS.md` at project root. Six specialized agent roles:

| Agent | Purpose | When to dispatch |
|---|---|---|
| `recon-agent` | Map attack surface (crawl, common files, hidden params) | Start of engagement or stale endpoints |
| `js-analyst` | JS secrets, DOM sinks/sources, hidden API endpoints | Parallel with recon |
| `vuln-scanner` | Test specific vuln category on assigned targets | After recon, one per category |
| `finding-verifier` | Re-verify findings, check exploitability | Session resume with stale findings |
| `payload-crafter` | Craft bypass payloads when standard attacks fail | When vuln-scanner reports filtering |
| `auth-tester` | IDOR matrix, auth bypass, race conditions, JWT | When multiple auth states available |

### Dispatch rules
- Never dispatch agents to the same endpoint simultaneously (WAF rate limiting)
- All agents share the same session (thread-safe in Java extension)
- Orchestrator merges results and makes strategic decisions — agents execute
- Max 3-4 agents simultaneously (MCP server processes requests sequentially)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BURP_API_HOST` | `127.0.0.1` | Extension API host |
| `BURP_API_PORT` | `8111` | Extension API port |
| `BURP_API_TIMEOUT` | `30` | HTTP timeout (seconds) |
| `BURP_MAX_RESPONSE_SIZE` | `50000` | Max response chars before truncation |

## Error Resolution

1. **Extension won't load**: Check Java 21+ JDK, verify JAR built with `mvn package`
2. **Port 8111 in use**: Another Burp instance or process using the port
3. **MCP connection fails**: Ensure extension is loaded and API server started (check Burp output log)
4. **"Is extension loaded?"**: Python client can't reach Java API — verify Burp is running with extension
5. **Scanner tools fail**: Requires Burp Suite Professional (not Community Edition)
6. **Collaborator tools fail**: Requires Burp Professional with Collaborator configured
