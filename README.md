# Burp Suite Swiss Knife MCP

Claude Code as your pentesting brain — connected to Burp Suite.

## Architecture

```mermaid
graph TB
    subgraph Target
        T[Web Application]
    end

    subgraph Burp Suite
        BS[Burp Proxy] -->|captures| PH[(Proxy History)]
        BS -->|passive scan| SC[(Scanner Findings)]
        BS -->|builds| SM[(Sitemap)]
        BScan[Burp Scanner] -->|active scan| SC
        SK[Swiss Knife Extension<br/>REST API :8111] -->|reads| PH
        SK -->|reads| SC
        SK -->|reads| SM
        SK -->|sends via| HTTP[Burp HTTP Client]
        HTTP -->|appears in| PH
        SK -->|collaborator| COLLAB[Burp Collaborator]
    end

    subgraph MCP Server
        MCP[Python MCP Server<br/>stdio transport] -->|HTTP calls| SK
        MCP -->|formats & truncates| PROC[Processing Layer]
    end

    subgraph Claude Code
        CC[Claude Code<br/>Pentesting Brain] <-->|MCP protocol| MCP
    end

    T <-->|traffic| BS
    HTTP -->|requests| T
    CC -->|"1. Read what Burp found"| MCP
    CC -->|"2. Analyze attack surface"| MCP
    CC -->|"3. Craft & send requests"| MCP
    CC -->|"4. Correlate findings"| MCP
    CC -->|"5. Document vulns"| MCP

    style CC fill:#7c3aed,color:#fff
    style SK fill:#f59e0b,color:#000
    style MCP fill:#3b82f6,color:#fff
    style T fill:#ef4444,color:#fff
```

## Workflow

```mermaid
flowchart LR
    A[1. Scope<br/>get_scope] --> B[2. Recon<br/>get_sitemap<br/>get_proxy_history<br/>get_scanner_findings]
    B --> C[3. Analyze<br/>extract_parameters<br/>find_injection_points<br/>get_unique_endpoints]
    C --> D[4. Prioritize<br/>Claude ranks by<br/>severity + params<br/>+ tech stack]
    D --> E[5. Test<br/>send_http_request<br/>resend_with_modification]
    E --> F{Blind<br/>vuln?}
    F -->|yes| G[6. OOB<br/>generate_collaborator_payload<br/>get_collaborator_interactions]
    F -->|no| H[7. Document<br/>save_finding<br/>export_report]
    G --> H
    E -->|iterate| C

    style A fill:#6366f1,color:#fff
    style B fill:#3b82f6,color:#fff
    style C fill:#0ea5e9,color:#fff
    style D fill:#14b8a6,color:#fff
    style E fill:#f59e0b,color:#000
    style G fill:#ef4444,color:#fff
    style H fill:#22c55e,color:#fff
```

## Component Interaction

```mermaid
sequenceDiagram
    participant CC as Claude Code
    participant MCP as MCP Server (Python)
    participant EXT as Burp Extension (Java)
    participant BURP as Burp Suite Core
    participant TGT as Target App

    Note over CC,TGT: Phase 1 — Read what Burp found
    CC->>MCP: get_proxy_history(filter_url="api")
    MCP->>EXT: GET /api/proxy/history?filter_url=api
    EXT->>BURP: api.proxy().history()
    BURP-->>EXT: List<ProxyHttpRequestResponse>
    EXT-->>MCP: JSON (truncated, formatted)
    MCP-->>CC: Compact table of matching requests

    Note over CC,TGT: Phase 2 — Analyze attack surface
    CC->>MCP: find_injection_points(index=42)
    MCP->>EXT: POST /api/analysis/injection-points
    EXT->>EXT: Detect reflected params, SQLi/XSS names, IDOR patterns
    EXT-->>MCP: Risk-scored injection points
    MCP-->>CC: Prioritized list of entry points

    Note over CC,TGT: Phase 3 — Test hypothesis (request goes through Burp)
    CC->>MCP: send_http_request(method="POST", url="...", body="id=1' OR 1=1--")
    MCP->>EXT: POST /api/http/send
    EXT->>BURP: api.http().sendRequest(request)
    BURP->>TGT: HTTP Request
    TGT-->>BURP: HTTP Response
    Note over BURP: Appears in HTTP History<br/>Passive scanner runs
    BURP-->>EXT: HttpRequestResponse
    EXT-->>MCP: Response JSON (truncated)
    MCP-->>CC: Status + headers + body

    Note over CC,TGT: Phase 4 — Document finding
    CC->>MCP: save_finding(title="SQLi in /api/users", severity="HIGH", evidence="...")
    MCP->>EXT: POST /api/notes/findings
    EXT-->>MCP: Finding saved (ID: 1)
    MCP-->>CC: Confirmed
```

## Setup

### 1. Build & Load the Burp Extension

```bash
cd burp-extension
mvn package
```

Load `target/burpsuite-swiss-knife-0.1.0.jar` in Burp Suite:
- **Extender → Add → Java → Select JAR**
- Verify: check Burp's output log for "Swiss Knife MCP started on port 8111"

### 2. Install the Python MCP Server

```bash
cd mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Configure Claude Code

Add to your Claude Code MCP settings (`~/.claude/claude_desktop_config.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "/absolute/path/to/mcp-server/.venv/bin/python",
      "args": ["-m", "burpsuite_mcp"]
    }
  }
}
```

## Tools (25 total)

### Read (what Burp found)
| Tool | Description |
|------|-------------|
| `get_proxy_history` | Proxy history with filters (URL, method, status) |
| `get_request_detail` | Full request/response for a history item |
| `get_scanner_findings` | Scanner findings by severity/confidence |
| `get_sitemap` | All discovered URLs from sitemap |
| `get_scope` | Current target scope |
| `check_scope` | Check if URL is in scope |

### Analyze (attack surface)
| Tool | Description |
|------|-------------|
| `extract_parameters` | All params from a request (query, body, cookie) |
| `extract_forms` | HTML forms and inputs from response |
| `extract_api_endpoints` | API paths, JS fetch calls, links |
| `find_injection_points` | Risk-scored injection points (SQLi, XSS, SSRF...) |
| `detect_tech_stack` | Server tech, frameworks, security headers |
| `get_unique_endpoints` | Deduplicated endpoints with parameter names |

### Send (through Burp → appears in HTTP history)
| Tool | Description |
|------|-------------|
| `send_http_request` | Send structured HTTP request through Burp |
| `send_raw_request` | Send raw HTTP bytes through Burp |
| `resend_with_modification` | Modify and resend a history request |
| `send_to_repeater` | Send request to Repeater tab |
| `send_to_intruder` | Send request to Intruder |

### Correlate
| Tool | Description |
|------|-------------|
| `search_history` | Search history by query, method, status |
| `get_findings_for_endpoint` | All findings for a specific URL |
| `get_response_diff` | Diff two responses |

### Collaborator (OOB testing)
| Tool | Description |
|------|-------------|
| `generate_collaborator_payload` | Generate Collaborator URL |
| `get_collaborator_interactions` | Check for DNS/HTTP/SMTP callbacks |

### Notes & Reporting
| Tool | Description |
|------|-------------|
| `save_finding` | Save a vulnerability finding |
| `get_findings` | List saved findings |
| `export_report` | Export as markdown or JSON |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BURP_API_HOST` | `127.0.0.1` | Burp extension host |
| `BURP_API_PORT` | `8111` | Burp extension port |
| `BURP_API_TIMEOUT` | `30` | Request timeout (seconds) |
| `BURP_MAX_RESPONSE_SIZE` | `50000` | Max response body chars |

## Requirements

- Burp Suite Professional (for scanner findings + collaborator) or Community
- Java 21+
- Python 3.11+
- Claude Code
