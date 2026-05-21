# Large-File Split + Gap Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split 7 oversized source files into focused submodules (behavior-preserving, shim-backed backwards compat) and land 4 gap fixes (Java test infra, audit log rotation, collaborator placeholder verification, recon overlap audit).

**Architecture:** Each split is one atomic commit with explicit `__all__` re-export shims (Python) or final-field collaborator classes (Java). MCP tool names, HTTP route paths, JSON shapes frozen. JUnit 5 for Java tests (test scope only — prod classpath stays zero-dep).

**Tech Stack:** Python 3.11+ / Hatch / FastMCP; Java 21 / Maven / Montoya / JUnit 5 (new).

**Baselines (verify before commit):**
- MCP `@mcp.tool` decorators: **219**
- Java `createContext` routes in `ApiServer.java`: **28**
- Python tests (uv run python -m unittest discover tests): **324** pass

---

## Task B2: Java test infrastructure (FIRST — enables later Java tests)

**Files:**
- Modify: `burp-extension/pom.xml`
- Create: `burp-extension/src/test/java/com/swissknife/analysis/MatcherEngineTest.java`
- Create: `burp-extension/src/test/java/com/swissknife/handlers/ScopeHandlerColdStartTest.java`

- [ ] **Step 1: Add JUnit 5 + Surefire to pom.xml**

Add to `<dependencies>`:
```xml
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.0</version>
    <scope>test</scope>
</dependency>
```

Add to `<build><plugins>`:
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>3.2.5</version>
</plugin>
```

- [ ] **Step 2: Write MatcherEngineTest covering `not_status` case**

```java
package com.swissknife.analysis;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.List;

class MatcherEngineTest {
    @Test
    void notStatusMatcherFiresWhenStatusDoesNotMatch() {
        Map<String, Object> matcher = Map.of(
            "type", "not_status",
            "status", List.of(200, 201, 204)
        );
        assertTrue(MatcherEngine.evaluate(matcher, 500, "body", Map.of(), "baseline", 100L, 100L, 1000, 1000));
        assertFalse(MatcherEngine.evaluate(matcher, 200, "body", Map.of(), "baseline", 100L, 100L, 1000, 1000));
    }

    @Test
    void unknownMatcherTypeFailsClosed() {
        Map<String, Object> matcher = Map.of("type", "nonexistent_matcher");
        assertFalse(MatcherEngine.evaluate(matcher, 200, "body", Map.of(), "baseline", 100L, 100L, 1000, 1000));
    }
}
```

Verify `MatcherEngine.evaluate` signature matches; adjust args if needed (read `MatcherEngine.java` first).

- [ ] **Step 3: Write ScopeHandlerColdStartTest**

```java
package com.swissknife.handlers;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class ScopeHandlerColdStartTest {
    @Test
    void coldStartReadsModeFromStateFile() throws Exception {
        Path intel = Paths.get(".burp-intel");
        Files.createDirectories(intel);
        Path state = intel.resolve("_scope_mode.json");
        Files.writeString(state, "{\"mode\":\"strict\"}");
        // Force re-evaluation via reflection or expose a package-private reload() if needed.
        // If static initializer already ran, this test documents the assumption — note in commit msg.
        assertEquals("strict", ScopeHandler.currentMode);
    }
}
```

If static initializer can't be re-triggered, document the limitation and expose `ScopeHandler.reloadMode()` as a package-private helper.

- [ ] **Step 4: Run tests**

Run: `cd burp-extension && mvn test`
Expected: BUILD SUCCESS, 3+ tests pass.

- [ ] **Step 5: Verify prod classpath unchanged**

Run: `cd burp-extension && mvn dependency:tree -Dscope=runtime`
Expected: junit-jupiter NOT in tree.

- [ ] **Step 6: Commit**

```bash
git add burp-extension/pom.xml burp-extension/src/test/
git commit -m "test(java): JUnit 5 + Surefire infra, matcher + scope cold-start tests"
```

---

## Task A3: Split advisor/assess.py (lowest-risk Python split)

**Files:**
- Modify: `mcp-server/src/burpsuite_mcp/tools/advisor/assess.py` (884 → ~150 lines, orchestrator only)
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q1_scope.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q2_repro.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q3_impact.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q4_dedup.py`
- Reference: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q5.py` (template — DO NOT modify)
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q6_never_submit.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q7_triager.py`
- Create: `mcp-server/tests/test_advisor_questions.py`

- [ ] **Step 1: Read q5.py to confirm pattern**

Read `mcp-server/src/burpsuite_mcp/tools/advisor_kb/q5.py` end-to-end. Note signature, return shape, dependencies.

- [ ] **Step 2: Define shared CheckResult TypedDict**

Add to `mcp-server/src/burpsuite_mcp/tools/advisor_kb/__init__.py`:
```python
from typing import TypedDict

class CheckResult(TypedDict):
    passed: bool
    reason: str
    evidence: dict
```

- [ ] **Step 3: Extract each question into its own module**

For each question (Q1-Q4, Q6, Q7) — open `advisor/assess.py`, find the block of code handling that question's logic, lift it into `advisor_kb/qN_<name>.py` as:

```python
from . import CheckResult

async def check(args) -> CheckResult:
    # ... lifted logic ...
    return {"passed": True, "reason": "...", "evidence": {...}}
```

Match q5.py's signature exactly. Pass the same args dict that assess.py currently constructs.

- [ ] **Step 4: Rewrite assess_finding_impl as orchestrator**

```python
from ..advisor_kb import q1_scope, q2_repro, q3_impact, q4_dedup, q5, q6_never_submit, q7_triager

async def assess_finding_impl(...):
    args = {...}  # construct shared args dict
    for name, mod in [("q1", q1_scope), ("q2", q2_repro), ("q3", q3_impact),
                       ("q4", q4_dedup), ("q5", q5), ("q6", q6_never_submit), ("q7", q7_triager)]:
        if name not in overrides_passed:
            result = await mod.check(args)
            if not result["passed"]:
                return reject(name, result)
    return accept(...)
```

- [ ] **Step 5: Write test for each question module**

```python
import unittest, asyncio
from burpsuite_mcp.tools.advisor_kb import q1_scope, q2_repro, q3_impact, q4_dedup, q6_never_submit, q7_triager

class TestAdvisorQuestions(unittest.TestCase):
    def test_q1_scope_passes_in_scope(self):
        args = {"endpoint": "https://example.com/api", "domain": "example.com", "scope_mode": "strict"}
        result = asyncio.run(q1_scope.check(args))
        self.assertIsInstance(result["passed"], bool)
    # ... one test per question ...
```

- [ ] **Step 6: Run full test suite**

Run: `cd mcp-server && uv run python -m unittest discover tests -v`
Expected: ≥324 + 6 new = 330 pass.

- [ ] **Step 7: Verify decorator count unchanged**

Run: `grep -rE "@mcp\\.tool" mcp-server/src | wc -l`
Expected: 219 (unchanged).

- [ ] **Step 8: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/tools/advisor/ mcp-server/src/burpsuite_mcp/tools/advisor_kb/ mcp-server/tests/test_advisor_questions.py
git commit -m "refactor(advisor): split assess.py 7-question gate into per-question modules"
```

---

## Task A4: Split research.py (6 backends → 6 modules + register)

**Files:**
- Delete: `mcp-server/src/burpsuite_mcp/tools/research.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/__init__.py` (shim + `register`)
- Create: `mcp-server/src/burpsuite_mcp/tools/research/exploitdb.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/osv.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/github_advisory.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/snyk.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/attackerkb.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/github_code.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/research/register.py`
- Create: `mcp-server/tests/test_research_dispatch.py`

- [ ] **Step 1: Read research.py end-to-end**

Map each `_<backend>_search` helper, the shared HTTP plumbing, and the `register(mcp)` decorators.

- [ ] **Step 2: Create package skeleton**

```bash
mkdir -p mcp-server/src/burpsuite_mcp/tools/research
```

Write `__init__.py`:
```python
"""Research backends — shim re-exports for backwards compat."""
from .exploitdb import _exploitdb_search
from .osv import _osv_search
from .github_advisory import _github_advisory_search
from .snyk import _snyk_db_search
from .attackerkb import _attackerkb_search
from .github_code import _github_code_search
from .register import register

__all__ = [
    "_exploitdb_search", "_osv_search", "_github_advisory_search",
    "_snyk_db_search", "_attackerkb_search", "_github_code_search",
    "register",
]
```

- [ ] **Step 3: Move each backend function into its own file**

Each file pattern:
```python
# exploitdb.py
"""Exploit-DB search backend."""
import httpx  # or whatever research.py uses
from .._common import ...  # if shared helpers exist, lift to _common.py

def _exploitdb_search(query: str) -> str:
    # ... lifted body verbatim ...
```

If shared HTTP helpers exist in research.py, lift to `research/_common.py` and import from each backend.

- [ ] **Step 4: Move register(mcp) to register.py**

```python
# register.py
from .exploitdb import _exploitdb_search
from .osv import _osv_search
# ... etc
from fastmcp import FastMCP

def register(mcp: FastMCP):
    @mcp.tool()
    async def research_attack_vector(...):
        # ... dispatch to backends ...
```

- [ ] **Step 5: Delete research.py**

```bash
rm mcp-server/src/burpsuite_mcp/tools/research.py
```

- [ ] **Step 6: Write smoke-import test**

```python
# test_research_dispatch.py
import unittest

class TestResearchShim(unittest.TestCase):
    def test_all_symbols_importable_via_old_path(self):
        from burpsuite_mcp.tools.research import (
            _exploitdb_search, _osv_search, _github_advisory_search,
            _snyk_db_search, _attackerkb_search, _github_code_search, register,
        )
        for sym in [_exploitdb_search, _osv_search, _github_advisory_search,
                    _snyk_db_search, _attackerkb_search, _github_code_search]:
            self.assertTrue(callable(sym))
```

- [ ] **Step 7: Verify server.py import unchanged**

```bash
grep -n "from .tools import research\|from .tools.research import\|tools.research" mcp-server/src/burpsuite_mcp/server.py
```
Confirm: no edits needed.

- [ ] **Step 8: Run tests + decorator count**

Run: `cd mcp-server && uv run python -m unittest discover tests -v`
Run: `grep -rE "@mcp\\.tool" mcp-server/src | wc -l`
Expected: 324+1 pass; decorator count 219.

- [ ] **Step 9: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/tools/research/ mcp-server/tests/test_research_dispatch.py
git rm mcp-server/src/burpsuite_mcp/tools/research.py
git commit -m "refactor(research): split 6 backends into research/ package with re-export shim"
```

---

## Task A5: Split cve.py

**Files:**
- Delete: `mcp-server/src/burpsuite_mcp/tools/cve.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/cve/__init__.py`
- Create: `mcp-server/src/burpsuite_mcp/tools/cve/match.py` (`_load_tech_vulns`, `_extract_version`, `_version_tuple`, `_version_in_range`, `_match_tech_to_vulns`)
- Create: `mcp-server/src/burpsuite_mcp/tools/cve/shodan.py` (`_shodan_cve_lookup`, `_shodan_cves_query`, `_shodan_cpe_lookup`, `_shodan_cpe_dict`)
- Create: `mcp-server/src/burpsuite_mcp/tools/cve/nvd.py` (`_nvd_lookup`)
- Create: `mcp-server/src/burpsuite_mcp/tools/cve/register.py` (all `@mcp.tool` defs)
- Create: `mcp-server/tests/test_cve_match.py`

- [ ] **Step 1: Read cve.py, identify shared state**

Identify any module-level caches (`_tech_vulns_cache` etc.). Lift to `cve/_cache.py` or keep in `match.py` if only used there.

- [ ] **Step 2: Create package + each submodule (follow A4 pattern)**

Same shim pattern. `__init__.py`:
```python
from .match import _load_tech_vulns, _extract_version, _version_tuple, _version_in_range, _match_tech_to_vulns
from .shodan import _shodan_cve_lookup, _shodan_cves_query, _shodan_cpe_lookup, _shodan_cpe_dict
from .nvd import _nvd_lookup
from .register import register
__all__ = [...]
```

- [ ] **Step 3: Write test for match logic**

```python
# test_cve_match.py
import unittest
from burpsuite_mcp.tools.cve.match import _version_in_range, _extract_version, _version_tuple

class TestCveMatch(unittest.TestCase):
    def test_version_in_range_inclusive(self):
        self.assertTrue(_version_in_range("2.4.50", "2.4.0-2.4.51"))
        self.assertFalse(_version_in_range("2.5.0", "2.4.0-2.4.51"))

    def test_extract_version_from_server_header(self):
        self.assertEqual(_extract_version("Apache/2.4.50"), "2.4.50")
```

Adapt to actual function behavior — read source first.

- [ ] **Step 4: Delete cve.py, run suite, commit**

```bash
rm mcp-server/src/burpsuite_mcp/tools/cve.py
cd mcp-server && uv run python -m unittest discover tests -v
git add mcp-server/src/burpsuite_mcp/tools/cve/ mcp-server/tests/test_cve_match.py
git rm mcp-server/src/burpsuite_mcp/tools/cve.py
git commit -m "refactor(cve): split into match/shodan/nvd submodules with re-export shim"
```

---

## Task A1: Split SessionHandler.java (HIGHEST RISK — 2021 lines)

**Files:**
- Modify: `burp-extension/src/main/java/com/swissknife/handlers/SessionHandler.java` (→ ~200 lines, router only)
- Create: `burp-extension/src/main/java/com/swissknife/store/SessionStore.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/SessionRequestExecutor.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/VariableExtractor.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/FlowRunner.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/AttackSurfaceDiscovery.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/AutoProbeOrchestrator.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/BatchProbeHandler.java`
- Create: `burp-extension/src/main/java/com/swissknife/session/SessionExtractHandler.java`
- Create: `burp-extension/src/test/java/com/swissknife/store/SessionStoreTest.java`
- Create: `burp-extension/src/test/java/com/swissknife/session/VariableExtractorTest.java`

- [ ] **Step 1: Read full SessionHandler.java (2021 lines)**

Map: field-by-field, method-by-method. Note which methods touch which fields. Build migration table.

- [ ] **Step 2: Extract SessionStore (state-only class)**

```java
package com.swissknife.store;

import com.swissknife.handlers.Session;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SessionStore {
    private static final SessionStore INSTANCE = new SessionStore();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public static SessionStore get() { return INSTANCE; }

    public Map<String, Session> getSessions() { return sessions; }
    public Session getSession(String name) { return sessions.get(name); }
    public void putSession(String name, Session s) { sessions.put(name, s); }
    public Session removeSession(String name) { return sessions.remove(name); }
    public List<String[]> getSessionInfoList() {
        // ... lifted from SessionHandler.getSessionInfoList ...
    }
}
```

`Session` class location — keep where it is. SessionStore only manages the map.

- [ ] **Step 3: Extract VariableExtractor (static utilities)**

```java
package com.swissknife.session;

public class VariableExtractor {
    private static final ThreadLocal<List<String>> _lastExtractWarnings = ThreadLocal.withInitial(ArrayList::new);

    public static String extractByRegex(String text, String regex) { ... }
    public static String simpleJsonExtract(String json, String path) { ... }
    public static Map<String, Object> interpolateStep(Map<String, Object> step, Map<String, String> variables) { ... }
    public static String interpolateString(String s, Map<String, String> variables) { ... }
    public static Map<String, String> extractFromResponse(HttpRequestResponse result, Map<String, Object> rules) { ... }
    public static void mergeVariables(Session session, Map<String, String> extracted) { ... }
}
```

- [ ] **Step 4: Extract SessionRequestExecutor**

```java
package com.swissknife.session;

public class SessionRequestExecutor {
    private final MontoyaApi api;

    public SessionRequestExecutor(MontoyaApi api) { this.api = api; }

    public HttpRequestResponse send(Session session, Map<String, Object> params) {
        // ... lifted from SessionHandler.sendSessionRequest ...
    }

    private void updateCookiesFromResponse(Session session, HttpRequestResponse result) { ... }
    private HttpRequest resolveBody(HttpRequest request, Map<String, Object> params, Map<String, String> variables) { ... }
    public Map<String, Object> buildResponseMap(HttpRequestResponse result) { ... }
    private URI buildSafeUri(String fullUrl) throws URISyntaxException { ... }
    private String extractTitle(String html) { ... }
}
```

- [ ] **Step 5: Extract FlowRunner**

```java
package com.swissknife.session;

public class FlowRunner {
    private final SessionRequestExecutor executor;

    public FlowRunner(SessionRequestExecutor executor) { this.executor = executor; }

    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        // ... lifted from SessionHandler.handleFlow ...
    }
}
```

- [ ] **Step 6: Extract AttackSurfaceDiscovery, AutoProbeOrchestrator, BatchProbeHandler, SessionExtractHandler**

Same pattern — one class per `handle*` method group. Lift private helpers (`scoreParamRisk`, `scoreEndpointRisk`, `detectTechFromResponse`, `selectAdaptivePayloads`, `detectReflection`, `detectErrorPatterns`, `injectParam`, `paramMatcherHits`) into the class that uses them. Shared helpers → `session/SessionUtils.java`.

- [ ] **Step 7: Rewrite SessionHandler as thin router**

```java
package com.swissknife.handlers;

import com.swissknife.server.BaseHandler;
import com.swissknife.store.SessionStore;
import com.swissknife.session.*;
import com.sun.net.httpserver.HttpExchange;
import java.util.Map;

public class SessionHandler extends BaseHandler {
    private final SessionStore store = SessionStore.get();
    private final SessionRequestExecutor executor;
    private final FlowRunner flowRunner;
    private final AttackSurfaceDiscovery discovery;
    private final AutoProbeOrchestrator autoProbe;
    private final BatchProbeHandler batch;
    private final SessionExtractHandler extract;

    public SessionHandler(MontoyaApi api) {
        super(api);
        this.executor = new SessionRequestExecutor(api);
        this.flowRunner = new FlowRunner(executor);
        this.discovery = new AttackSurfaceDiscovery(api, executor);
        this.autoProbe = new AutoProbeOrchestrator(api, executor);
        this.batch = new BatchProbeHandler(api, executor);
        this.extract = new SessionExtractHandler();
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        Map<String, Object> body = readJsonBody(exchange);

        switch (path) {
            case "/api/session/create" -> handleCreate(exchange, body);
            case "/api/session/request" -> executor.handle(exchange, body, store);
            case "/api/session/extract" -> extract.handle(exchange, body, store);
            case "/api/session/flow" -> flowRunner.handle(exchange, body);
            case "/api/session/list" -> handleList(exchange);
            case "/api/session/probe" -> batch.handleProbe(exchange, body);
            case "/api/session/batch" -> batch.handleBatch(exchange, body);
            case "/api/session/discover" -> discovery.handle(exchange, body);
            case "/api/session/auto-probe" -> autoProbe.handle(exchange, body);
            default -> {
                if (path.startsWith("/api/session/last-host/")) handleLastHost(exchange, path.substring(23));
                else if (path.startsWith("/api/session/delete/")) handleDelete(exchange, path.substring(20));
                else sendError(exchange, 404, "unknown_route", "no such session route");
            }
        }
    }

    // create, list, lastHost, delete remain inline (simple, ~30 lines each)
}
```

Match the existing path strings exactly. Read original `handleRequest` to confirm path routing.

- [ ] **Step 8: Write JUnit tests**

```java
// SessionStoreTest.java
class SessionStoreTest {
    @Test
    void singletonReturnsSameInstance() {
        assertSame(SessionStore.get(), SessionStore.get());
    }

    @Test
    void putAndGetSession() {
        SessionStore store = SessionStore.get();
        Session s = new Session("test", ...);
        store.putSession("test", s);
        assertSame(s, store.getSession("test"));
        store.removeSession("test");
    }
}

// VariableExtractorTest.java
class VariableExtractorTest {
    @Test
    void interpolateReplacesVariables() {
        Map<String, String> vars = Map.of("token", "abc123");
        assertEquals("Bearer abc123", VariableExtractor.interpolateString("Bearer {{token}}", vars));
    }

    @Test
    void regexExtractsFirstGroup() {
        String body = "csrf_token=xyz789;";
        assertEquals("xyz789", VariableExtractor.extractByRegex(body, "csrf_token=([a-z0-9]+)"));
    }
}
```

- [ ] **Step 9: Build + test**

Run: `cd burp-extension && mvn clean package`
Run: `cd burp-extension && mvn test`
Expected: BUILD SUCCESS, JUnit 5+ passing.

- [ ] **Step 10: Verify route count unchanged**

Run: `grep -c "createContext" burp-extension/src/main/java/com/swissknife/server/ApiServer.java`
Expected: 28.

- [ ] **Step 11: Smoke test the Java side**

If feasible, load the new JAR in Burp and call `/api/session/list` — verify route still responds. If not feasible, document in commit message.

- [ ] **Step 12: Commit**

```bash
git add burp-extension/src/main/java/com/swissknife/store/SessionStore.java \
        burp-extension/src/main/java/com/swissknife/session/ \
        burp-extension/src/main/java/com/swissknife/handlers/SessionHandler.java \
        burp-extension/src/test/java/com/swissknife/store/SessionStoreTest.java \
        burp-extension/src/test/java/com/swissknife/session/VariableExtractorTest.java
git commit -m "refactor(session): split SessionHandler.java (2021 lines) into store + 7 collaborators"
```

---

## Task A6: Split AttackHandler.java

**Files:**
- Modify: `burp-extension/src/main/java/com/swissknife/handlers/AttackHandler.java` (→ thin router)
- Create: `burp-extension/src/main/java/com/swissknife/attack/AuthMatrixHandler.java`
- Create: `burp-extension/src/main/java/com/swissknife/attack/RaceHandler.java`
- Create: `burp-extension/src/main/java/com/swissknife/attack/HppHandler.java`
- Create: `burp-extension/src/main/java/com/swissknife/attack/AttackContext.java` (if shared state present)
- Create: `burp-extension/src/test/java/com/swissknife/attack/AuthMatrixHandlerTest.java` (smoke)

- [ ] **Step 1: Read AttackHandler.java, identify routes**

`grep "case \"" burp-extension/src/main/java/com/swissknife/handlers/AttackHandler.java` to find dispatch table.

- [ ] **Step 2: Check for shared state**

If field-level state is shared across attacks (e.g., a results map), extract to `AttackContext.java`:
```java
public class AttackContext {
    private final MontoyaApi api;
    // shared fields
    public AttackContext(MontoyaApi api) { this.api = api; }
}
```

If no shared state, skip AttackContext — pass `api` directly to each handler.

- [ ] **Step 3: Extract per-attack handlers**

Pattern per attack (e.g., auth-matrix):
```java
package com.swissknife.attack;

public class AuthMatrixHandler {
    private final MontoyaApi api;
    public AuthMatrixHandler(MontoyaApi api) { this.api = api; }

    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        // ... lifted from AttackHandler.handleAuthMatrix ...
    }
}
```

- [ ] **Step 4: Rewrite AttackHandler as router**

```java
public class AttackHandler extends BaseHandler {
    private final AuthMatrixHandler authMatrix;
    private final RaceHandler race;
    private final HppHandler hpp;

    public AttackHandler(MontoyaApi api) {
        super(api);
        this.authMatrix = new AuthMatrixHandler(api);
        this.race = new RaceHandler(api);
        this.hpp = new HppHandler(api);
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        switch (exchange.getRequestURI().getPath()) {
            case "/api/attack/auth-matrix" -> authMatrix.handle(exchange, readJsonBody(exchange));
            case "/api/attack/race" -> race.handle(exchange, readJsonBody(exchange));
            case "/api/attack/hpp" -> hpp.handle(exchange, readJsonBody(exchange));
            // ... any other routes ...
            default -> sendError(exchange, 404, "unknown_route", "no such attack route");
        }
    }
}
```

Match path strings to existing routes — read original first.

- [ ] **Step 5: Build + test + commit**

```bash
cd burp-extension && mvn clean package && mvn test
git add burp-extension/src/main/java/com/swissknife/attack/ \
        burp-extension/src/main/java/com/swissknife/handlers/AttackHandler.java \
        burp-extension/src/test/java/com/swissknife/attack/
git commit -m "refactor(attack): split AttackHandler.java per attack class"
```

---

## Task A7: Split ConfigTab.java

**Files:**
- Modify: `burp-extension/src/main/java/com/swissknife/ui/ConfigTab.java` (→ ~100 lines, JTabbedPane composition only)
- Create: `burp-extension/src/main/java/com/swissknife/ui/ScopePanel.java`
- Create: `burp-extension/src/main/java/com/swissknife/ui/InterceptPanel.java`
- Create: `burp-extension/src/main/java/com/swissknife/ui/MatchReplacePanel.java`
- Create: per additional tab discovered (read `ConfigTab.java` to enumerate)

- [ ] **Step 1: Read ConfigTab.java, enumerate panels**

Find every `JTabbedPane.addTab` call. Each tab corresponds to a panel-extraction target.

- [ ] **Step 2: Extract each panel**

Pattern:
```java
package com.swissknife.ui;

import javax.swing.*;
import burp.api.montoya.MontoyaApi;

public class ScopePanel extends JPanel {
    public ScopePanel(MontoyaApi api) {
        super();
        // ... lifted UI construction code from ConfigTab ...
    }
}
```

If panels share UI state, pass a shared model object into each ctor — do not use static state.

- [ ] **Step 3: Rewrite ConfigTab as composer**

```java
public class ConfigTab extends JPanel {
    public ConfigTab(MontoyaApi api) {
        super(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Scope", new ScopePanel(api));
        tabs.addTab("Intercept", new InterceptPanel(api));
        tabs.addTab("Match/Replace", new MatchReplacePanel(api));
        // ... other tabs ...
        add(tabs, BorderLayout.CENTER);
    }
}
```

- [ ] **Step 4: Build (no test — manual UI smoke only)**

Run: `cd burp-extension && mvn clean package`
Expected: BUILD SUCCESS.

Document in commit message: "Manual UI smoke required — load JAR in Burp, verify all tabs render."

- [ ] **Step 5: Commit**

```bash
git add burp-extension/src/main/java/com/swissknife/ui/
git commit -m "refactor(ui): split ConfigTab.java into per-tab panel classes"
```

---

## Task A2: Split recon/scanning.py (LATE — depends on B4 audit)

**Files:**
- Read first: `mcp-server/src/burpsuite_mcp/tools/recon/scanning.py` (full 1004 lines)
- Create package: `mcp-server/src/burpsuite_mcp/tools/recon/scanning/` directory
- Move: `scanning.py` → `scanning/__init__.py` (shim) + per-family submodules

- [ ] **Step 1: Read scanning.py end-to-end**

Inline `@mcp.tool` defs inside `register(mcp)` — list each tool. Group by family:
- Subdomain enumeration (subfinder, amass, crt.sh)
- Directory busting (ffuf, gobuster wrappers)
- Vulnerability scanning (nuclei, nikto)
- Crawling (katana, gau, wayback)
- DNS / Whois / cert lookups
- Tool inventory + SecLists detection

- [ ] **Step 2: Create per-family submodules**

```
recon/scanning/
  __init__.py       # re-export shim + register(mcp) that delegates
  subdomain.py      # @mcp.tool defs for subfinder, amass, crt.sh
  dirbust.py        # ffuf, gobuster
  vuln_scan.py      # nuclei, nikto
  crawl.py          # katana, gau, wayback
  dns_intel.py      # dns, whois, certs
  inventory.py      # check_recon_tools, detect_seclists, _cache_seclists
```

Each submodule has its own `register(mcp)`. Top-level `__init__.py`:
```python
from . import subdomain, dirbust, vuln_scan, crawl, dns_intel, inventory
from .inventory import detect_seclists, _cache_seclists  # re-export for tests

def register(mcp):
    subdomain.register(mcp)
    dirbust.register(mcp)
    vuln_scan.register(mcp)
    crawl.register(mcp)
    dns_intel.register(mcp)
    inventory.register(mcp)
```

- [ ] **Step 3: Verify import paths in callers**

```bash
grep -rn "from .*recon.scanning import\|from .*recon import scanning" mcp-server/src mcp-server/tests
```

Update any breakage; preserve shim re-exports.

- [ ] **Step 4: Run tests + verify decorator count**

Run: `cd mcp-server && uv run python -m unittest discover tests -v`
Run: `grep -rE "@mcp\\.tool" mcp-server/src | wc -l`
Expected: 324+ pass; decorator count 219.

- [ ] **Step 5: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/tools/recon/scanning/
git rm mcp-server/src/burpsuite_mcp/tools/recon/scanning.py
git commit -m "refactor(recon): split scanning.py (1004 lines) into per-family submodules"
```

---

## Task B1: Audit log rotation

**Files:**
- Modify: `burp-extension/src/main/java/com/swissknife/audit/ScopeAuditLog.java`
- Create: `burp-extension/src/test/java/com/swissknife/audit/ScopeAuditLogRotationTest.java`

- [ ] **Step 1: Add rotateIfNeeded() to ScopeAuditLog.java**

```java
package com.swissknife.audit;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

public class ScopeAuditLog {
    private static final long MAX_SIZE = 10L * 1024 * 1024;  // 10 MB
    private static final int MAX_ARCHIVES = 5;

    public static synchronized void append(String tool, String url, String mode) {
        Path log = intelDir().resolve("_audit.log");
        rotateIfNeeded(log);
        String line = buildJsonLine(tool, url, mode);
        try {
            Files.writeString(log, line + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // swallow — audit log failure must not break tool calls
        }
    }

    private static void rotateIfNeeded(Path log) {
        try {
            if (!Files.exists(log)) return;
            long size = Files.readAttributes(log, BasicFileAttributes.class).size();
            if (size < MAX_SIZE) return;

            Path dir = log.getParent();
            String base = log.getFileName().toString();

            // shift archives: .4 -> .5 (drop), .3 -> .4, ..., .1 -> .2
            for (int i = MAX_ARCHIVES - 1; i >= 1; i--) {
                Path src = dir.resolve(base + "." + i);
                Path dst = dir.resolve(base + "." + (i + 1));
                if (Files.exists(src)) {
                    Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // current -> .1
            Files.move(log, dir.resolve(base + ".1"), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // swallow
        }
    }

    private static Path intelDir() { ... existing ... }
    private static String buildJsonLine(...) { ... existing ... }
}
```

- [ ] **Step 2: Write rotation test**

```java
package com.swissknife.audit;

import org.junit.jupiter.api.*;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class ScopeAuditLogRotationTest {
    @TempDir Path tmpDir;

    @Test
    void rotatesWhenLogExceeds10MB() throws Exception {
        // Use system property or reflection to point at tmpDir
        Path log = tmpDir.resolve(".burp-intel/_audit.log");
        Files.createDirectories(log.getParent());
        // Pre-fill log with 11 MB
        byte[] chunk = new byte[1024];
        try (var os = Files.newOutputStream(log, StandardOpenOption.CREATE)) {
            for (int i = 0; i < 11 * 1024; i++) os.write(chunk);
        }
        // Trigger via append
        ScopeAuditLog.append("test", "https://example.com", "operator");
        assertTrue(Files.exists(log.resolveSibling("_audit.log.1")));
        assertTrue(Files.size(log) < 1024 * 1024);  // current log small after rotation
    }
}
```

Note: requires injection point for intelDir() — either pass system property or expose package-private setter.

- [ ] **Step 3: Build + test + commit**

```bash
cd burp-extension && mvn clean package && mvn test
git add burp-extension/src/main/java/com/swissknife/audit/ScopeAuditLog.java \
        burp-extension/src/test/java/com/swissknife/audit/
git commit -m "feat(audit): scope audit log rotation at 10MB, keep 5 archives"
```

---

## Task B3: Collaborator placeholder wiring verification

**Files:**
- Read: 7 KB files (state_machine_race.json, oauth_dpop_confused_deputy.json, edge_worker_ssrf.json, webauthn_passkey_attacks.json, cache_deception_v2.json, dom_clobbering_2024.json, service_worker_attacks.json)
- Read: `mcp-server/src/burpsuite_mcp/tools/scan/auto_probe.py` — find `_substitute_collaborator`
- Create: `mcp-server/tests/test_collaborator_substitution.py`

- [ ] **Step 1: Grep KB files for placeholders**

```bash
grep -lE "COLLABORATOR_URL|\\{\\{collaborator\\}\\}" mcp-server/src/burpsuite_mcp/knowledge/{state_machine_race,oauth_dpop_confused_deputy,edge_worker_ssrf,webauthn_passkey_attacks,cache_deception_v2,dom_clobbering_2024,service_worker_attacks}.json
```

- [ ] **Step 2: Read auto_probe.py substitution logic**

Find the function that replaces `{{collaborator}}` / `COLLABORATOR_URL` in probe payloads before send.

- [ ] **Step 3: Write substitution test**

```python
import unittest
from burpsuite_mcp.tools.scan.auto_probe import _substitute_collaborator  # adjust import

class TestCollaboratorSubstitution(unittest.TestCase):
    def test_substitutes_double_brace_placeholder(self):
        probe = {"payload": "GET / HTTP/1.1\\r\\nHost: {{collaborator}}\\r\\n\\r\\n"}
        result = _substitute_collaborator(probe, "abc123.oastify.com")
        self.assertIn("abc123.oastify.com", result["payload"])
        self.assertNotIn("{{collaborator}}", result["payload"])

    def test_substitutes_url_placeholder(self):
        probe = {"payload": "http://COLLABORATOR_URL/x"}
        result = _substitute_collaborator(probe, "abc123.oastify.com")
        self.assertIn("abc123.oastify.com", result["payload"])
```

Adjust to actual function name and signature.

- [ ] **Step 4: If any placeholder is uncovered, document in MEMORY.md and the spec's Findings section. Code fix is out-of-scope for B3 (B3 is verification only).**

- [ ] **Step 5: Run tests + commit**

```bash
cd mcp-server && uv run python -m unittest discover tests -v
git add mcp-server/tests/test_collaborator_substitution.py
git commit -m "test(collab): verify collaborator placeholder substitution covers 7 new KB files"
```

---

## Task B4: recon overlap audit (doc-only)

**Files:**
- Read: `mcp-server/src/burpsuite_mcp/tools/recon/scanning.py`
- Read: `mcp-server/src/burpsuite_mcp/tools/recon_extended.py`
- Append to: `docs/specs/2026-05-21-large-file-split-and-gap-fixes-design.md` → "## Findings: recon overlap audit"

- [ ] **Step 1: List all `@mcp.tool` decorators in both files**

```bash
grep -nE "@mcp\\.tool|async def" mcp-server/src/burpsuite_mcp/tools/recon/scanning.py mcp-server/src/burpsuite_mcp/tools/recon_extended.py
```

- [ ] **Step 2: Build tool inventory table**

For each tool, identify: name, purpose, dependencies, target external binary.

- [ ] **Step 3: Mark overlaps**

Two tools are overlapping if they invoke the same external binary or produce the same output shape.

- [ ] **Step 4: Append findings to spec**

```markdown
## Findings: recon overlap audit (2026-05-21)

Tools in `recon/scanning.py`: [list]
Tools in `recon_extended.py`: [list]

Confirmed overlaps:
- (none) / or specific tool names

Recommendation: [merge / keep separate / dedupe via shared helper]
```

- [ ] **Step 5: Commit**

```bash
git add docs/specs/2026-05-21-large-file-split-and-gap-fixes-design.md
git commit -m "docs(recon): overlap audit between scanning.py and recon_extended.py"
```

---

## Task C1: Update CLAUDE.md

- [ ] **Step 1: Re-verify counts**

```bash
grep -rE "@mcp\\.tool" mcp-server/src | wc -l                    # MCP tools (decorator count)
ls mcp-server/src/burpsuite_mcp/knowledge/*.json | wc -l         # KB files
ls .claude/skills/*.md | wc -l                                    # skills
ls .claude/rules/*.md | wc -l                                     # rules
```

- [ ] **Step 2: Update CLAUDE.md:45 if any count drifted**

- [ ] **Step 3: Update "Adding New Features" section if module paths shifted**

E.g., `cve.py` → `cve/` package: update example references.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude.md): refresh counts and module-path references post-refactor"
```

---

## Task C2: Update MEMORY.md

- [ ] **Step 1: Append refactor section**

Edit `/home/tyrus/.claude/projects/-home-tyrus-Github-burpsuite-swiss-knife-mcp/memory/MEMORY.md`:

```markdown
## Refactor (2026-05-21)

Large-file splits (7 files, ~7000 lines):
- SessionHandler.java 2021 → store/SessionStore + 7 session/ collaborators (router ~200)
- recon/scanning.py 1004 → recon/scanning/ package (6 families)
- advisor/assess.py 884 → orchestrator + 6 new advisor_kb/qN_*.py
- research.py 841 → research/ package (6 backends + register)
- cve.py 816 → cve/ package (match/shodan/nvd/register)
- AttackHandler.java 789 → attack/ package (per-attack handlers)
- ConfigTab.java 757 → ui/ per-panel classes

Gap fixes:
- B1: ScopeAuditLog rotation (10MB × 5 archives)
- B2: JUnit 5 + Surefire (test scope only, prod classpath unchanged)
- B3: Collaborator placeholder substitution verified for 7 new KB files
- B4: recon overlap audit (see docs/specs/2026-05-21-large-file-split-and-gap-fixes-design.md)

All splits preserve public APIs via re-export shims (Python) or path-frozen routers (Java).
HTTP route count unchanged: 28 createContext. MCP tool count unchanged: 219.
```

- [ ] **Step 2: No commit needed (memory file is outside repo).**

---

## Final Verification

- [ ] All 13 commits land on `main`
- [ ] `mvn clean package` + `mvn test` green
- [ ] `uv run python -m unittest discover tests -v` ≥ 324 + new tests pass
- [ ] `grep -rE "@mcp\\.tool" mcp-server/src | wc -l` = 219
- [ ] `grep -c "createContext" burp-extension/src/main/java/com/swissknife/server/ApiServer.java` = 28
- [ ] No source file > 500 lines (run `find src -name "*.py" -o -name "*.java" | xargs wc -l | awk '$1 > 500'` — should be empty)
- [ ] Push: `git push origin main`
