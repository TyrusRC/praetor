---
name: playbook-source-review
description: White-box methodology — strip noise → inventory routes → grep sinks → trace source→sink → rank unauth surface → confirm live. Load when the operator has read access to the target's source tree (SOW-provided repo, leaked archive, open-source component, decompiled app).
prerequisite: A local source tree on disk (`git clone`, tarball, or export). No source = wrong playbook; use the black/grey-box router instead.
stop_condition: 10 tool calls producing SAST findings but zero source→sink chain that maps to a reachable endpoint → stop grepping, switch to DAST on the routes you already inventoried. SAST that never hands off to a live probe is a linting report, not a pentest.
---

# White-Box Source Review Playbook

Source access changes the order of operations. Don't discover what you can read.
Read the routes, read the sinks, trace input to the sink, then confirm the trace
against the live target. SAST finds candidates; only DAST (Rule 10, `confirm_*`)
produces a reportable finding.

Complements `security-research.md` (which greps GitHub for sink shapes in *similar*
codebases). This playbook is for when you hold the *actual* source of the target.

## Pipeline

```
0. Reduce      strip vendor/generated noise               (operator shell pre-step)
1. Inventory   route declarations → endpoints.json        inventory_source_routes
2. Sink map    per-language dangerous-sink grep            run_opengrep_source
3. Trace       input → sink data-flow                      run_vulnhuntr / run_xvulnhuntr
4. Rank        unauth-reachable sinks first                sast_to_endpoint_risk / risk_rank_endpoints
5. Confirm     source-flagged sink → live proof            confirm_rce / confirm_sqli / confirm_ssti / ...
6. Save        chain source_chain + logger_index           save_finding
```

Steps 1-4 are cheap and non-touching (no traffic to target). Step 5 is where a
candidate becomes a finding — and the only step that generates a `logger_index`.

## Step 0 — Reduce the tree (operator pre-step, not a Praetor tool)

Praetor has **no** code-size-reduction tool. Do it in the shell before analysis so
opengrep / vulnhuntr spend LLM/scan budget on first-party code, not dependencies:

```bash
# Inspect what dominates the tree first.
du -sh */ | sort -rh | head

# Analyse a copy with dependency + generated dirs excluded.
rsync -a --exclude={node_modules,vendor,.git,dist,build,target,.next,site-packages,\
__pycache__,.venv,venv,third_party,generated,migrations,test,tests,spec,fixtures} \
  ./repo/ /tmp/repo-src/
```

`inventory_source_routes` and `risk_rank_endpoints` already prune the common
dependency dirs internally (`node_modules .git .venv venv env __pycache__ dist
build vendor .next target site-packages`). `run_opengrep_source` does **not** —
it runs opengrep against `target_path` verbatim, so point it at the reduced copy
(or drop a `.semgrepignore`). Vendor code you didn't write is noise: a CVE in a
dependency is a `playbook-cve-research.md` job, not a source-review finding.

## Step 1 — Inventory routes from source

The crawler only sees what it clicked. Source route declarations expose the routes
it never reached (admin, cron, webhook, internal, feature-flagged).

```
inventory_source_routes(source_dir="/tmp/repo-src", domain="target.com")
```

Regex-scans for route declarations and **merges** them into
`<domain>/endpoints.json` (dedup by method+path, tagged `discovered_via:
source_route_inventory`). Returns `{files_scanned, routes_found, by_framework,
routes:[{method,path,framework,source:"file:line"}]}`.

**Coverage — verify before trusting.** The route regex fires only for:

| Framework | Declaration pattern | Ext scanned |
|---|---|---|
| Flask / Quart | `@app.route("/x")`, `@bp.route(..., methods=[...])` | `.py` |
| FastAPI / Starlette / Sanic | `@app.get("/x")`, `@router.post("/x")` | `.py` |
| Express / Koa / Fastify | `app.get("/x", h)`, `router.post("/x", h)` | `.js .jsx .ts .tsx .mjs .cjs` |
| Spring | `@GetMapping`, `@PostMapping`, `@RequestMapping("/x")` | `.java .kt` |
| Rails | verbs in `config/routes.rb` | `.rb` |

Source extensions scanned: `.py .js .jsx .ts .tsx .mjs .cjs .java .kt .rb` **only**.
PHP, .NET (`.cs`), Go, Perl, C++ route declarations are **not** matched — for those
stacks, inventory routes by hand (see the sink table's grep column) or via OWASP
Noir (`check_recon_tools`). It is a regex, not an AST: it misses dynamically-built
routes (loops, `add_url_rule`, blueprint prefixes, decorator factories) and
over-matches commented-out decorators. Treat the output as leads to verify with
`curl_request` / `probe_hosts`, not as ground truth.

## Step 2 — Per-language dangerous-sink reference

The sink dictates the vuln class and the `confirm_*` that closes the loop. `grep`
column is for stacks `run_opengrep_source` under-covers or `inventory_source_routes`
doesn't parse. Walk from each sink **backwards** to the request parameter that feeds
it — an unsanitized path is a candidate, a sink fed only by constants is not.

### Command execution → `confirm_rce`
| Lang | Sinks |
|---|---|
| PHP | `system` `exec` `shell_exec` `passthru` `proc_open` `popen` `` `backtick` `` |
| Java | `Runtime.exec` `ProcessBuilder` `GroovyShell.evaluate` |
| .NET | `Process.Start` `ProcessStartInfo` |
| Node | `child_process.exec` `execSync` `spawn(...,{shell:true})` |
| Python | `os.system` `subprocess.*(shell=True)` `os.popen` `commands.*` |
| Go | `exec.Command` `exec.CommandContext` (with shell wrapper) |
| Perl | `system` `exec` `open("cmd|")` `` qx// `` `` `backtick` `` |
| C/C++ | `system` `popen` `execve`/`execlp` with concatenated argv |

### SQL string-concat → `confirm_sqli`
| Lang | Sinks |
|---|---|
| PHP | `mysqli_query`/`$pdo->query` with `.$var`; `mysql_query` |
| Java | `Statement.executeQuery(str+...)`; string-built JPQL/HQL |
| .NET | `SqlCommand(str+...)`; `FromSqlRaw`/`ExecuteSqlRaw` with interpolation |
| Node | `db.query("... "+x)`; `sequelize.query` w/ template literal |
| Python | `cursor.execute(f"... {x}")`; `.raw()` / `.extra()` with %-format |
| Go | `db.Query(fmt.Sprintf(...))`; string-built query |
| Perl | `$dbh->do("... $x")`; `prepare` with interpolation |

### Template injection → `confirm_ssti`
| Lang | Sinks |
|---|---|
| PHP | Twig `createTemplate($userInput)`; Smarty `->fetch("string:".$x)` |
| Java | Thymeleaf/FreeMarker/Velocity template from request; SpEL `parseExpression` |
| .NET | Razor `RazorEngine.Compile(userStr)` |
| Node | `pug.compile`/`ejs.render`/`handlebars.compile` on user string |
| Python | Jinja2 `render_template_string(x)`; `Template(x).render()` |

### File include / path traversal / LFI → `test_lfi` then `confirm_rce` if RCE-chainable
| Lang | Sinks |
|---|---|
| PHP | `include`/`require`/`file_get_contents`/`fopen`($var); `phar://` |
| Java | `new File(base+req)`; `Files.newInputStream`; `getResourceAsStream` |
| .NET | `File.ReadAllText`/`Path.Combine(root, userSeg)` w/o canonicalisation |
| Node | `fs.readFile`/`res.sendFile`/`require(userPath)` |
| Python | `open(base+x)`; `send_file`; `os.path.join(root, x)` (abs override) |
| Go | `os.Open`/`http.ServeFile(w,r,userPath)` |
| C/C++ | `fopen`/`open` with concatenated path, no `realpath` check |

### Deserialization → see `playbook-deserialization.md`
| Lang | Sinks |
|---|---|
| PHP | `unserialize($_COOKIE/$_POST)` |
| Java | `ObjectInputStream.readObject`; Jackson `enableDefaultTyping` |
| .NET | `BinaryFormatter.Deserialize`; `LosFormatter`; `Json.NET TypeNameHandling` |
| Node | `node-serialize.unserialize`; `JSON.parse` reviver |
| Python | `pickle.loads`; `yaml.load` (no `SafeLoader`) |
| Ruby | `Marshal.load`; `YAML.load` |

### Unsafe reflection / dynamic dispatch → `confirm_rce` (attacker-chosen class/method executes)
Its own confirmed gap: an attacker-controlled class name or callback string reaches
a reflective invoker, letting them instantiate/invoke arbitrary code paths — often
the last hop of a deserialization or mass-assignment chain.
| Lang | Sinks |
|---|---|
| Java | `Class.forName(userStr)` → `newInstance`; `Method.invoke`; `MethodHandles` with request-derived name |
| .NET | `Type.GetType(userStr)`; `Activator.CreateInstance(userType)`; `Assembly.Load`; `MethodInfo.Invoke` |
| PHP | `call_user_func($_GET['fn'], ...)`; `call_user_func_array`; `$fn()` / `new $cls()` variable-class; `ReflectionClass($userStr)` |
| Node | `global[userKey](...)`; `require(userModule)`; `Function(userStr)` |
| Python | `getattr(obj, userAttr)()`; `__import__(userMod)`; `importlib.import_module(x)` |

### SSRF → `confirm_ssrf`
Outbound fetch fed by request input: `curl_exec`/`file_get_contents(url)` (PHP),
`URL.openConnection`/`HttpClient` (Java), `WebClient`/`HttpClient` (.NET),
`axios`/`fetch`/`http.get(userUrl)` (Node), `requests.get`/`urllib` (Python),
`http.Get` (Go). Trace the URL argument back to the parameter.

### XXE → `confirm_xxe`
XML parser with external entities enabled: `DocumentBuilderFactory` /`SAXParser`
without `disallow-doctype-decl` (Java), `XmlDocument`/`XmlReader` with
`DtdProcessing.Parse` (.NET), `libxml_disable_entity_loader(false)` / `simplexml`
(PHP), `lxml.etree` with `resolve_entities=True` (Python).

## Step 3 — Trace source → sink

Three engines, different depths. Pick by language and budget:

| Tool | Engine | Languages | Speed | Use when |
|---|---|---|---|---|
| `run_opengrep_source` | opengrep/semgrep rules (pattern, no LLM) | all (registry rulesets) | fast | **first pass** — breadth. Grep every sink class, cheap, deterministic. |
| `run_vulnhuntr` | protectai/vulnhuntr, LLM-chain | **Python only** | medium | Python target, or cross-check opengrep's Python hits with data-flow reasoning. |
| `run_xvulnhuntr` | CompassSecurity fork, LLM AST chain-trace | **Python + C# + Java** | slow | typed source→sink chains in Py/C#/Java that pattern rules can't follow across functions. |

```
# Breadth first — deterministic, no API key.
run_opengrep_source(target_path="/tmp/repo-src")
# default configs: p/owasp-top-ten + p/security-audit
# add language packs: extra_configs=["p/java","p/python","p/javascript","p/secrets"]
# CI pivot: sarif=True → SARIF JSON

# Depth on the language-matched sink chains (needs ANTHROPIC_API_KEY / local LLM).
run_xvulnhuntr(repo_path="/tmp/repo-src", language="java", max_files=50)   # Py/C#/Java
run_vulnhuntr(repo_path="/tmp/repo-src", max_files=50)                     # Python only
```

`run_opengrep_source` returns a **text summary** (or SARIF). The LLM tools return
`{findings:[{vuln_type, severity, file, line, sink, source_chain:[{file,line,symbol}],
explanation}]}` — the `source_chain` is what you project into
`save_finding.evidence.source_chain` after DAST confirms it.

**Prefer opengrep for breadth, an LLM tool for the one chain you'll confirm.** Don't
run all three on the whole tree; that's three scans for one answer. Run opengrep, let
it point at the hot files, then run the LLM tracer scoped to them.

## Step 4 — Rank unauth-reachable sinks first

A sink behind admin auth is a lower-priority finding than the same sink on an
unauthenticated route. Rank by reachability × severity before you touch the target.

```
# One-shot: run opengrep --json + rank. Easiest path.
risk_rank_endpoints(target_path="/tmp/repo-src")

# Or, if you already captured opengrep --json separately, transform it:
sast_to_endpoint_risk(opengrep_json="/tmp/og.json", source_root="/tmp/repo-src")
```

Both return `{total_findings, ranked_endpoints:[{method, path, framework, risk_score,
vuln_classes, evidence:[...]}], orphans:[...]}` — findings grouped by the nearest
route decorator walked back from each finding's line, summed risk, worst-first.
`risk_rank_endpoints` runs opengrep internally (`--json`); `sast_to_endpoint_risk`
is the pure transformer — feed it opengrep run with `--json` (not the text summary
from `run_opengrep_source` default; either capture `--json` yourself or use the
one-shot). `source_root` is **required** for the route walk-back; without it, route
inference falls back to filesystem-only (Next.js `app/`/`pages/`).

**Prioritise:** unauthenticated routes with `vuln_classes` in {rce, sqli, ssti, ssrf,
deserialization} and the highest `risk_score`. Cross-check each top route against
`business_context` — an unauth RCE on a money-flow endpoint outranks an authed one on
a settings page. `orphans` are sinks with no resolvable route: grep the file to find
how it's reached before dismissing.

## Step 5 — Confirm the source-flagged sink against the live target

**This is the only step that makes it a finding.** A source trace is a hypothesis
with a file:line; Rule 10 needs a live `logger_index`. Fire the `confirm_*` matched
to the sink class, against the ranked endpoint + the parameter you traced:

| Source-flagged class | Confirm tool | Benign proof |
|---|---|---|
| command exec / unsafe reflection | `confirm_rce(endpoint, parameter, command="id")` | unique marker in output, or `use_collaborator=True` for blind |
| SQL string-concat | `confirm_sqli(endpoint, parameter, dbms="postgres")` | `VERSION()` / `CURRENT_USER()` w/ marker (Rule 7 — never `SELECT *`) |
| template injection | `confirm_ssti(endpoint, parameter, engine="jinja2")` | engine-specific math expression evaluates |
| SSRF | `confirm_ssrf(endpoint, parameter, protocols=["http","dns"])` | Collaborator callback |
| XXE | `confirm_xxe(endpoint, mode="inband")` | reads `/etc/hostname` (Rule 7 — not `/etc/passwd`) |

Pass a `session=` name for authed routes (grey-box). All route through Burp, so each
produces a `logger_index` / `collaborator_interaction_id`. If the source said
"vulnerable" but the confirm fails, the input is sanitised on the live path (WAF,
middleware, a validator the trace missed) — record a documented negative with
`record_probe_outcome`, don't file it. Source is the map; the live confirm is the
territory.

## Step 6 — Save with the source chain attached

```python
save_finding(
    vuln_type="sqli",
    endpoint="https://target.com/api/report",
    parameter="sort",
    severity="high",
    title="SQL injection in /api/report sort parameter (source-confirmed)",
    impact="Unauthenticated DB read; CURRENT_USER() + VERSION() extracted. "
           "Query built by string concat at ReportDao.java:88 with no bind param.",
    evidence={
        "logger_index": N,                    # the confirm_sqli replay — REQUIRED
        "source_chain": [                      # from run_xvulnhuntr / manual trace
            {"file": "controllers/ReportController.java", "line": 41, "symbol": "sort param"},
            {"file": "dao/ReportDao.java", "line": 88, "symbol": "executeQuery(str+sort)"},
        ],
        "summary": "sort → ReportController:41 → ReportDao.executeQuery:88 (concat, no PreparedStatement)",
        "reproductions": [ {"logger_index": ..., "elapsed_ms": ..., "status_code": ...} ],
    },
)
```

The `logger_index` is the DAST confirm (Rule 10b). `source_chain` is corroboration,
not a substitute — a chain with no live `logger_index` is not reportable.

## Anti-patterns

- **Don't file SAST output as findings.** opengrep/vulnhuntr produce candidates. No
  `confirm_*` + `logger_index` = no finding. `assess_finding` hard-rejects.
- **Don't scan vendor code.** A CVE in a dependency → `playbook-cve-research.md`.
  Reduce the tree (Step 0) first.
- **Don't trust the route regex.** `inventory_source_routes` misses dynamic routes
  and doesn't parse PHP/.NET/Go/Perl/C++ routes at all — verify liveness before probing.
- **Don't run all three tracers on the whole tree.** opengrep for breadth, one LLM
  tool scoped to the hot files it flagged.
- **Don't probe auth'd sinks before unauth ones.** Rank with `sast_to_endpoint_risk`;
  unauthenticated RCE/SQLi is where the impact (and the bounty) is.
- **Don't cite a `source_chain` without a live confirm.** Source proves the code path
  exists; only DAST proves it's reachable and exploitable on the deployed build.

## Cross-references

- `security-research.md` — GitHub sink-pattern search + the patch-diff section for
  when you hold source of both the vulnerable and fixed versions.
- `playbook-deserialization.md` — magic-byte ID + gadget chains for the deserial row.
- `playbook-cve-research.md` — dependency CVEs (co-load; source-review is first-party code).
- `playbook-router.md` — Rule 28 white-box mindset entry point.
- Rule 10 / `verify-finding.md` — the confirm→assess→save gate every candidate passes.
- Rule 7 — benign proof only (`VERSION()`, `/etc/hostname`), never real-data exfil.
