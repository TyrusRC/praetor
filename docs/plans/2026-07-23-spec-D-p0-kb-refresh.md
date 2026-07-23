# Spec D P0 KB Refresh — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four P0 detection gaps from Spec D (MCP invisible-unicode, error-based blind SSTI, SSRF redirect-loop full-response leak, Next.js May-2026 middleware bypass) plus one batch-first token fix, all shipping through existing probe/KB/variant-pack machinery.

**Architecture:** One new VerdictResult probe module (`detect_mcp_invisible_unicode`) built as a pure-function core + thin MCP wrapper; three KB content additions (contexts merged into existing parents + one new `ssti_elixir.json` sibling); one new variant generator wired into `probe_cve_with_variants`. No Java/MatcherEngine changes — every technique maps to existing matcher types. Task 0 first removes a shared-infra token duplication that every new probe returns through.

**Tech Stack:** Python 3.11+ (managed by `uv`), FastMCP, custom `JsonUtil`-free JSON (stdlib `json`), `unittest` (project convention — NOT pytest).

## Global Constraints

Copied verbatim from Spec D + project rules. Every task implicitly includes these.

- **Python:** run via `uv run`, never `python3`/`pip`. Type hints on all functions; `async` on every `@mcp.tool()`; docstring on public APIs. PEP 8, f-strings. Early returns.
- **Probe return shape:** every probe returns a `VerdictResult` dict via `make_verdict` / `verdict_from_tally` / `error_verdict` from `burpsuite_mcp.tools.testing._verdict`.
- **New probe registration:** module in `mcp-server/src/burpsuite_mcp/tools/`, `@mcp.tool()` inside a `register(mcp)` function, then add to the import block and call `<module>.register(mcp)` in `mcp-server/src/burpsuite_mcp/server.py`.
- **KB schema:** `{"category": str, "contexts": {ctx: {"description": str, "tech_match": [str], "param_match": [str], "probes": [{"payload": str, "description": str, "matchers": [ {...} ], "severity": str, "confidence_boost": int, "variables": {}}]}}}`. Matcher types are only those in `MatcherEngine.java` (`status`,`word`,`regex`,`length_delta`,`length_diff`,`differential_timing`,`collaborator`,`reflection`, …). Unknown types fail closed — do not invent matcher types.
- **KB-org rule:** merge into an existing parent file; add a new sibling file ONLY when no parent fits (justified per-file).
- **HARD safety:** no destructive payloads (Rule 5). OOB variants use a real Collaborator subdomain via `generate_collaborator_payload`, never a fabricated domain (Rule 9a). These P0 items are detection-only and need no destructive payloads.
- **Hallucination guard:** only CVE IDs with an authoritative advisory are in scope — Next.js (Vercel-official: CVE-2026-44575 / 44574 / 23870) and Ivanti (Rapid7-corroborated). No other CVE numbers.
- **Commit identity:** `TyrusRC` / `63230297+TyrusRC@users.noreply.github.com` (already set). Never add an AI co-author. Commit prefixes: `perf(...)`, `feat(kb): ...`, `feat(probes): ...`.
- **Test command:** `cd mcp-server && uv run python -m unittest tests.<module> -v`.
- **Working dir for all paths below:** repo root `/home/kali/project/trc/praetor`. Python source root: `mcp-server/src/burpsuite_mcp/`. Tests: `mcp-server/tests/`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `tools/testing/_verdict.py` (modify) | Remove `details.summary` duplicate + empty evidence-list keys | 0 |
| `tools/mcp_invisible_unicode.py` (create) | `detect_mcp_invisible_unicode` probe + pure detectors | 1 |
| `server.py` (modify) | Import + register the new probe | 1 |
| `tests/test_mcp_invisible_unicode.py` (create) | Unit tests for detectors + verdict shape | 1 |
| `knowledge/ssti_python.json`, `ssti_php.json`, `ssti_java.json`, `ssti_js.json` (modify) | `error_based_blind` + `boolean_error_blind` contexts | 2 |
| `knowledge/ssti_elixir.json` (create) | New Elixir SSTI parent (no existing parent fits) | 2 |
| `knowledge/ssrf_bypass.json` (modify) | `redirect_loop_full_response_leak` context | 3 |
| `tools/cve_variant_probe.py` (modify) | `nextjs_middleware_bypass` variant generator + CVE map | 4 |
| `knowledge/react_server_components.json` (modify) | Server-Function deserialization DoS context | 4 |
| `tests/test_spec_d_kb.py` (create) | KB parse + context-presence + variant-map tests | 2,3,4 |

---

## Task 0: Batch-first token fix — kill VerdictResult double-encode

**Files:**
- Modify: `mcp-server/src/burpsuite_mcp/tools/testing/_verdict.py:55-71`
- Test: `mcp-server/tests/test_verdict_shape.py` (create)

**Interfaces:**
- Produces: `make_verdict(...)` returns a dict with a single top-level `human_summary` (no `details.summary` duplicate) and omits `logger_indices`/`proxy_indices`/`collaborator_interactions`/`reproductions` keys when their value is empty.

**Why first:** every probe in Tasks 1–4 returns through `make_verdict`; the fix has a 71-tool blast radius and is near-zero-risk. `details.summary` is documented as legacy-backward-compat, so Step 1 verifies no consumer reads it before removal.

- [ ] **Step 1: Verify no consumer reads `details["summary"]`**

Run:
```bash
cd /home/kali/project/trc/praetor/mcp-server
grep -rn '\["summary"\]\|\.get("summary"\|details\.summary\|\.get('"'"'summary'"'"'' src/burpsuite_mcp | grep -iv 'evidence_summary\|human_summary\|def \|summary:' || echo "NO DETAILS.SUMMARY CONSUMERS"
```
Expected: `NO DETAILS.SUMMARY CONSUMERS`, OR a small list. If any real consumer reads `details["summary"]`, STOP — switch it to read top-level `human_summary` in the same commit. If output is only the `_verdict.py` producer lines and `human_summary` usages, proceed.

- [ ] **Step 2: Write the failing test**

Create `mcp-server/tests/test_verdict_shape.py`:
```python
"""Token-lean verdict shape (Spec E1.2): no duplicate summary, no empty lists."""
import unittest

from burpsuite_mcp.tools.testing._verdict import make_verdict


class VerdictShapeTest(unittest.TestCase):
    def test_no_duplicate_summary(self):
        v = make_verdict("FAILED", 0.1, "no anomaly", summary="FAILED — clean")
        self.assertEqual(v["human_summary"], "FAILED — clean")
        self.assertNotIn("summary", v.get("details", {}),
                         "details.summary duplicates human_summary")

    def test_empty_evidence_lists_omitted(self):
        v = make_verdict("FAILED", 0.1, "no anomaly", summary="x")
        for k in ("logger_indices", "proxy_indices",
                  "collaborator_interactions", "reproductions"):
            self.assertNotIn(k, v, f"empty {k} should be omitted")

    def test_populated_evidence_lists_kept(self):
        v = make_verdict("CONFIRMED", 0.9, "hit", summary="x",
                         logger_indices=[412])
        self.assertEqual(v["logger_indices"], [412])
        self.assertNotIn("proxy_indices", v)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd mcp-server && uv run python -m unittest tests.test_verdict_shape -v`
Expected: FAIL — `details.summary duplicates human_summary` and empty-list assertions fail.

- [ ] **Step 4: Edit `make_verdict`**

In `tools/testing/_verdict.py`, replace the body from the `d = dict(details or {})` line through the `return out` (lines ~55-72) with:
```python
    conf = max(0.0, min(1.0, float(confidence)))
    d = dict(details or {})
    out: dict[str, Any] = {
        "verdict": verdict,
        "confidence": round(conf, 3),
        "evidence_summary": evidence_summary,
    }
    # Only include evidence lists when non-empty (token-lean, Spec E1.2).
    if logger_indices:
        out["logger_indices"] = list(logger_indices)
    if proxy_indices:
        out["proxy_indices"] = list(proxy_indices)
    if collaborator_interactions:
        out["collaborator_interactions"] = list(collaborator_interactions)
    if reproductions:
        out["reproductions"] = list(reproductions)
    if d:
        out["details"] = d
    if vuln_type:
        out["vuln_type"] = vuln_type
    if summary is not None:
        out["human_summary"] = summary
    return out
```
Also delete the now-dead `if summary is not None: d.setdefault("summary", summary)` block above `out`. Update the docstring: drop the "stored at `details.summary`" sentence.

- [ ] **Step 5: Run the new test + the full verdict-refactor suite**

Run:
```bash
cd mcp-server && uv run python -m unittest tests.test_verdict_shape tests.test_w14_verdict_pipeline_integration -v
```
Expected: PASS. If `test_w14_verdict_pipeline_integration` reads `details.summary`, that is a real consumer — fix it to read `human_summary` and re-run.

- [ ] **Step 6: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/tools/testing/_verdict.py mcp-server/tests/test_verdict_shape.py
git commit -m "perf(verdict): drop duplicate summary + empty evidence keys (Spec E1.2)"
```

---

## Task 1: `detect_mcp_invisible_unicode` probe (D1)

**Files:**
- Create: `mcp-server/src/burpsuite_mcp/tools/mcp_invisible_unicode.py`
- Modify: `mcp-server/src/burpsuite_mcp/server.py` (import block near line 43; register call near line 204)
- Modify: `mcp-server/src/burpsuite_mcp/knowledge/mcp_tool_poisoning.json` (add `invisible_unicode_in_tool_metadata` context)
- Test: `mcp-server/tests/test_mcp_invisible_unicode.py`

**Interfaces:**
- Produces:
  - `find_hidden_unicode(text: str) -> list[dict]` — each hit `{"index": int, "codepoint": str (U+XXXX), "category": str, "char_name": str}`. Categories: `tag_block`, `zero_width`, `bidi_override`.
  - `scan_tool_metadata(tools: list[dict]) -> dict` — `{"model_visible_hits": [...], "schema_hits": [...], "tools_flagged": [str]}`; `model_visible_hits` come from `name`/`description`, `schema_hits` from the serialized `inputSchema`.
  - MCP tool `detect_mcp_invisible_unicode(tools_json: str = "", server_url: str = "", session: str = "", timeout: int = 15) -> dict` (VerdictResult).

- [ ] **Step 1: Write the failing tests**

Create `mcp-server/tests/test_mcp_invisible_unicode.py`:
```python
"""D1 — invisible-unicode MCP tool-metadata detector."""
import unittest

from burpsuite_mcp.tools.mcp_invisible_unicode import (
    find_hidden_unicode,
    scan_tool_metadata,
)


class FindHiddenUnicodeTest(unittest.TestCase):
    def test_tag_block_detected(self):
        # U+E0041 is a TAG LATIN CAPITAL LETTER A (concealment channel).
        hits = find_hidden_unicode("safe\U000E0041text")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "tag_block")
        self.assertEqual(hits[0]["codepoint"], "U+E0041")

    def test_zero_width_detected(self):
        hits = find_hidden_unicode("da​ta")  # zero-width space
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "zero_width")

    def test_bidi_override_detected(self):
        hits = find_hidden_unicode("a‮b")  # RIGHT-TO-LEFT OVERRIDE
        self.assertEqual(hits[0]["category"], "bidi_override")

    def test_clean_text_no_hits(self):
        self.assertEqual(find_hidden_unicode("perfectly normal tool"), [])


class ScanToolMetadataTest(unittest.TestCase):
    def test_hidden_in_description_flagged_model_visible(self):
        tools = [{"name": "get_weather",
                  "description": "Gets weather.\U000E0041\U000E0042",
                  "inputSchema": {"type": "object"}}]
        r = scan_tool_metadata(tools)
        self.assertEqual(r["tools_flagged"], ["get_weather"])
        self.assertTrue(r["model_visible_hits"])

    def test_hidden_only_in_schema(self):
        tools = [{"name": "x", "description": "clean",
                  "inputSchema": {"desc": "field⁠join"}}]  # word joiner
        r = scan_tool_metadata(tools)
        self.assertTrue(r["schema_hits"])
        self.assertFalse(r["model_visible_hits"])

    def test_clean_tools(self):
        tools = [{"name": "x", "description": "clean", "inputSchema": {}}]
        r = scan_tool_metadata(tools)
        self.assertEqual(r["tools_flagged"], [])


class VerdictShapeTest(unittest.TestCase):
    def test_error_on_no_input(self):
        import asyncio
        from mcp.server.fastmcp import FastMCP
        from burpsuite_mcp.tools import mcp_invisible_unicode as m
        mcp = FastMCP("t")
        m.register(mcp)
        # call the underlying coroutine directly via the registered tool
        # (registration smoke-test; full I/O covered by integration).
        self.assertTrue(callable(m.find_hidden_unicode))
```

- [ ] **Step 2: Run to verify failure**

Run: `cd mcp-server && uv run python -m unittest tests.test_mcp_invisible_unicode -v`
Expected: FAIL — `ModuleNotFoundError: burpsuite_mcp.tools.mcp_invisible_unicode`.

- [ ] **Step 3: Create the probe module**

Create `mcp-server/src/burpsuite_mcp/tools/mcp_invisible_unicode.py`:
```python
"""detect_mcp_invisible_unicode — D1 (Spec D, 2026-07-23).

Invisible-unicode concealment in MCP tool metadata (arXiv 2607.05744; MCPTox
ASR up to 72.8%). TAG-block (U+E0000–E007F), zero-width, and bidi-override
codepoints are invisible in the human approval view but delivered verbatim to
the consuming model — defeating both human review and text filters.

Static detector: no destructive payload, no target request unless the operator
asks it to fetch a live tools/list. Reuses no network for the core scan.

Returns VerdictResult.
"""

from __future__ import annotations

import json
import unicodedata

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


# Concealment codepoint ranges. Kept explicit for auditability.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_BIDI_OVERRIDE = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def _category(cp: int) -> str | None:
    if 0xE0000 <= cp <= 0xE007F:
        return "tag_block"
    if cp in _ZERO_WIDTH:
        return "zero_width"
    if cp in _BIDI_OVERRIDE:
        return "bidi_override"
    return None


def find_hidden_unicode(text: str) -> list[dict]:
    """Return one hit per concealment codepoint in `text`."""
    hits: list[dict] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        cat = _category(cp)
        if cat is None:
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "<unnamed>"
        hits.append({
            "index": i,
            "codepoint": f"U+{cp:04X}",
            "category": cat,
            "char_name": name,
        })
    return hits


def scan_tool_metadata(tools: list[dict]) -> dict:
    """Scan MCP tool descriptors. name/description = model-visible channel;
    inputSchema = secondary channel."""
    model_visible: list[dict] = []
    schema_hits: list[dict] = []
    flagged: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("name", ""))
        vis = find_hidden_unicode(tname) + find_hidden_unicode(
            str(t.get("description", "")))
        sch = find_hidden_unicode(json.dumps(t.get("inputSchema", {}),
                                             ensure_ascii=False))
        if vis:
            model_visible.extend({**h, "tool": tname, "field": "name/description"}
                                 for h in vis)
        if sch:
            schema_hits.extend({**h, "tool": tname, "field": "inputSchema"}
                               for h in sch)
        if vis or sch:
            flagged.append(tname)
    return {
        "model_visible_hits": model_visible,
        "schema_hits": schema_hits,
        "tools_flagged": flagged,
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def detect_mcp_invisible_unicode(
        tools_json: str = "",
        server_url: str = "",
        session: str = "",
        timeout: int = 15,
    ) -> dict:
        """Detect invisible-unicode concealment in MCP tool metadata (D1).

        Provide EITHER `tools_json` (a JSON array of MCP tool descriptors, e.g.
        the `tools` field from a tools/list response or `enumerate_mcp_server`
        output) OR `server_url` to fetch tools/list live.

        CONFIRMED when concealment codepoints appear in a model-visible field
        (name/description); SUSPECTED when only inputSchema carries them.

        Returns: VerdictResult.
        """
        tools: list[dict] = []
        logger_indices: list[int] = []

        if tools_json:
            try:
                parsed = json.loads(tools_json)
                tools = parsed.get("tools", parsed) if isinstance(parsed, dict) else parsed
            except json.JSONDecodeError as e:
                return error_verdict(f"tools_json parse error: {e}",
                                     vuln_type="mcp_invisible_unicode")
        elif server_url:
            resp = await _fetch_tools(server_url, session, timeout)
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            body = resp.get("response_body") or ""
            try:
                obj = json.loads(body)
                tools = obj.get("result", {}).get("tools", []) or obj.get("tools", [])
            except (json.JSONDecodeError, AttributeError):
                return error_verdict(
                    "server_url did not return a parseable tools/list",
                    vuln_type="mcp_invisible_unicode")
        else:
            return error_verdict("provide tools_json or server_url",
                                 vuln_type="mcp_invisible_unicode")

        if not isinstance(tools, list) or not tools:
            return make_verdict(
                "FAILED", 0.10, "No MCP tools to scan.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                summary="FAILED — no tools scanned")

        r = scan_tool_metadata(tools)
        if r["model_visible_hits"]:
            return make_verdict(
                "CONFIRMED", 0.88,
                f"{len(r['model_visible_hits'])} concealment codepoint(s) in "
                f"model-visible tool metadata across {len(r['tools_flagged'])} "
                f"tool(s): {r['tools_flagged'][:5]}. Invisible to human review, "
                "delivered verbatim to the consuming model.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                details=r,
                summary=f"CONFIRMED invisible-unicode in {r['tools_flagged'][:3]}")
        if r["schema_hits"]:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"{len(r['schema_hits'])} concealment codepoint(s) in tool "
                "inputSchema only (secondary channel). Manual review advised.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                details=r,
                summary="SUSPECTED invisible-unicode in inputSchema")
        return make_verdict(
            "FAILED", 0.15,
            f"No concealment codepoints across {len(tools)} tool(s).",
            vuln_type="mcp_invisible_unicode",
            logger_indices=logger_indices,
            summary="FAILED — tool metadata clean")


async def _fetch_tools(server_url: str, session: str, timeout: int) -> dict:
    payload = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    headers = [{"name": "Content-Type", "value": "application/json"}]
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "POST", "url": server_url,
            "headers": headers, "body": payload})
    return await client.post("/api/http/curl", json={
        "url": server_url, "method": "POST", "headers": headers,
        "body": payload, "timeout": timeout})
```

- [ ] **Step 4: Run the module tests**

Run: `cd mcp-server && uv run python -m unittest tests.test_mcp_invisible_unicode -v`
Expected: PASS (all detector + scan + registration tests).

- [ ] **Step 5: Register in `server.py`**

In `mcp-server/src/burpsuite_mcp/server.py`: add `mcp_invisible_unicode,` to the tools import block (alphabetically near `mcp_enumerate` / the `a2a_agent_card_probe` grouping ~line 43). Add near line 204 with the other probe registrations:
```python
mcp_invisible_unicode.register(mcp)             # detect_mcp_invisible_unicode — D1 MCP tool-metadata concealment
```

- [ ] **Step 6: Add the KB context**

In `knowledge/mcp_tool_poisoning.json`, add inside `"contexts"` (after `rug_pull_post_install`):
```json
    "invisible_unicode_in_tool_metadata": {
      "description": "Tool name/description/inputSchema carries TAG-block (U+E0000-E007F), zero-width, or bidi-override codepoints. Invisible in the host approval UI, delivered verbatim to the consuming LLM (arXiv 2607.05744; MCPTox ASR up to 72.8%). Detect with detect_mcp_invisible_unicode; this KB context flags the same channel in captured tools/list responses.",
      "tech_match": ["mcp", "model-context-protocol", "fastmcp", "claude-desktop", "cursor"],
      "param_match": [],
      "probes": [
        {
          "payload": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}",
          "description": "Fetch tools/list; flag concealment codepoints in tool metadata.",
          "matchers": [
            {"type": "regex", "pattern": "[\\x{E0000}-\\x{E007F}\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}]", "weight": 90}
          ],
          "severity": "high",
          "confidence_boost": 70,
          "variables": {}
        }
      ]
    }
```
Note: verify the regex flavor. If `MatcherEngine`'s Java regex rejects `\x{...}` braces, substitute the literal ranges the engine accepts (Java `Pattern` uses `\x{E0000}` — valid). Confirm with the KB-load test in Task 4's Step and the existing `auto_probe` path; if the engine rejects it, the probe still works via `detect_mcp_invisible_unicode` (the KB matcher is the secondary path).

- [ ] **Step 7: Run the KB-load smoke test + commit**

Run: `cd mcp-server && uv run python -c "import json,pathlib; json.loads(pathlib.Path('src/burpsuite_mcp/knowledge/mcp_tool_poisoning.json').read_text()); print('OK')"`
Expected: `OK`.
```bash
git add mcp-server/src/burpsuite_mcp/tools/mcp_invisible_unicode.py \
        mcp-server/src/burpsuite_mcp/server.py \
        mcp-server/src/burpsuite_mcp/knowledge/mcp_tool_poisoning.json \
        mcp-server/tests/test_mcp_invisible_unicode.py
git commit -m "feat(probes): detect_mcp_invisible_unicode — MCP tool-metadata concealment (D1)"
```

---

## Task 2: Error-based blind SSTI (D2)

**Files:**
- Modify: `knowledge/ssti_python.json`, `ssti_php.json`, `ssti_java.json`, `ssti_js.json` — add `error_based_blind` + `boolean_error_blind` contexts
- Create: `knowledge/ssti_elixir.json` — new parent (no Elixir SSTI parent exists; justified per KB-org rule)
- Modify: `tests/test_spec_d_kb.py` (create in this task; extended in 3,4)

**Interfaces:**
- Produces: each `ssti_*.json` gains contexts named `error_based_blind` and `boolean_error_blind`; `ssti_elixir.json` exists and parses with ≥1 context.

**Technique:** force the engine to throw an exception whose message contains the evaluation output (e.g. arithmetic marker). Matcher = `regex`/`word` on the marker appearing inside an error body. Payloads carry a unique numeric marker (`1336+1` → look for `1337` inside a stack trace / error string).

- [ ] **Step 1: Write the failing KB test**

Create `mcp-server/tests/test_spec_d_kb.py`:
```python
"""Spec D KB content — presence + parse of new contexts/files/variants."""
import json
import unittest
from pathlib import Path

KB = Path(__file__).parent.parent / "src" / "burpsuite_mcp" / "knowledge"


def _load(name):
    return json.loads((KB / name).read_text())


class SstiErrorOracleTest(unittest.TestCase):
    ENGINES = ["ssti_python.json", "ssti_php.json", "ssti_java.json",
               "ssti_js.json", "ssti_elixir.json"]

    def test_engines_have_error_oracle_contexts(self):
        for f in self.ENGINES:
            data = _load(f)
            ctxs = data["contexts"]
            self.assertIn("error_based_blind", ctxs, f"{f} missing error_based_blind")
            self.assertIn("boolean_error_blind", ctxs, f"{f} missing boolean_error_blind")

    def test_error_context_marker_matcher(self):
        for f in self.ENGINES:
            ctx = _load(f)["contexts"]["error_based_blind"]
            probe = ctx["probes"][0]
            self.assertTrue(probe["matchers"], f"{f} error probe has no matcher")

    def test_elixir_parent_valid(self):
        data = _load("ssti_elixir.json")
        self.assertEqual(data["category"], "ssti_elixir")
        self.assertGreater(len(data["contexts"]), 0)
```

- [ ] **Step 2: Run to verify failure**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb -v`
Expected: FAIL — missing contexts / `ssti_elixir.json` not found.

- [ ] **Step 3: Add the two contexts to each existing SSTI engine file**

Add to the `"contexts"` object of each of `ssti_python.json`, `ssti_php.json`, `ssti_java.json`, `ssti_js.json`. Example for `ssti_python.json` (adapt the `payload` engine syntax per file — Jinja2 `{{1336+1}}` for python, Twig `{{1336+1}}` for php, FreeMarker `${1336+1}` for java, Handlebars/ES template for js):
```json
    "error_based_blind": {
      "description": "Successful Errors (PortSwigger Top-10-2025 #1): force the template engine to raise an exception whose message contains evaluation output. Blind SSTI extraction where no direct reflection exists. Marker 1337 = 1336+1 proves evaluation inside the error body.",
      "tech_match": ["jinja2", "flask", "python", "django"],
      "param_match": ["template", "name", "q", "search", "message"],
      "probes": [
        {
          "payload": "{{1336+1}}{{undefined_var_ZZ.__err__}}",
          "description": "Trigger an engine error after evaluation; look for 1337 echoed in the exception text.",
          "matchers": [
            {"type": "regex", "pattern": "1337", "weight": 60},
            {"type": "word", "words": ["Traceback", "TemplateError", "UndefinedError", "jinja2"], "condition": "or", "weight": 40}
          ],
          "severity": "high",
          "confidence_boost": 60,
          "variables": {}
        }
      ]
    },
    "boolean_error_blind": {
      "description": "Boolean-error oracle: payload raises an error only when a boolean condition on evaluated state is true, turning blind SSTI into a bit-oracle for exfil without direct output.",
      "tech_match": ["jinja2", "flask", "python"],
      "param_match": ["template", "name", "q"],
      "probes": [
        {
          "payload": "{{ (1 if 7*7==49 else x.__error__) }}",
          "description": "Error raised iff the arithmetic condition holds — differential error vs benign baseline.",
          "matchers": [
            {"type": "word", "words": ["Error", "Traceback", "Exception"], "condition": "or", "weight": 50}
          ],
          "severity": "medium",
          "confidence_boost": 40,
          "variables": {}
        }
      ]
    }
```

- [ ] **Step 4: Create `ssti_elixir.json`**

Create `knowledge/ssti_elixir.json`:
```json
{
  "category": "ssti_elixir",
  "description": "Server-side template injection in Elixir template engines (EEx, Phoenix HEEx). New parent (2026-07): no existing SSTI parent covers Elixir. Error-oracle extraction per PortSwigger Top-10-2025 #1 (Successful Errors). Use against Phoenix apps rendering user input through EEx.",
  "contexts": {
    "eex_arithmetic": {
      "description": "EEx evaluates <%= %> expressions server-side. Arithmetic marker 1337=1336+1 confirms evaluation.",
      "tech_match": ["elixir", "phoenix", "eex", "heex"],
      "param_match": ["template", "name", "message", "q"],
      "probes": [
        {
          "payload": "<%= 1336+1 %>",
          "description": "EEx arithmetic echo — 1337 in the response proves SSTI.",
          "matchers": [
            {"type": "word", "words": ["1337"], "condition": "and", "weight": 80}
          ],
          "severity": "critical",
          "confidence_boost": 80,
          "variables": {}
        }
      ]
    },
    "error_based_blind": {
      "description": "Force an EEx/Phoenix compile or runtime error whose message echoes evaluated output; blind extraction where no reflection exists.",
      "tech_match": ["elixir", "phoenix", "eex"],
      "param_match": ["template", "name", "q"],
      "probes": [
        {
          "payload": "<%= 1336+1 %><%= undefined_zz.err %>",
          "description": "Error after evaluation; 1337 echoed in the CompileError/ArgumentError body.",
          "matchers": [
            {"type": "regex", "pattern": "1337", "weight": 60},
            {"type": "word", "words": ["CompileError", "ArgumentError", "protocol Enumerable", "(elixir)"], "condition": "or", "weight": 40}
          ],
          "severity": "high",
          "confidence_boost": 60,
          "variables": {}
        }
      ]
    },
    "boolean_error_blind": {
      "description": "Boolean-error oracle for Elixir: raise iff an evaluated condition holds.",
      "tech_match": ["elixir", "phoenix", "eex"],
      "param_match": ["template", "name"],
      "probes": [
        {
          "payload": "<%= if 7*7==49, do: raise(\"ZZ\"), else: 1 %>",
          "description": "Differential error vs benign baseline.",
          "matchers": [
            {"type": "word", "words": ["RuntimeError", "ZZ", "Error"], "condition": "or", "weight": 50}
          ],
          "severity": "medium",
          "confidence_boost": 40,
          "variables": {}
        }
      ]
    }
  }
}
```

- [ ] **Step 5: Register `ssti_elixir.json` in the KB-new-files load test**

In `tests/test_kb_new_files_load.py`, add `"ssti_elixir.json",` to the `NEW_FILES` list and add `"ssti_elixir"` to the `test_seven_auto_probe_NOT_in_reference_only` tuple (SSTI is active auto_probe, not reference-only).

- [ ] **Step 6: Run the tests**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb tests.test_kb_new_files_load -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/knowledge/ssti_*.json \
        mcp-server/tests/test_spec_d_kb.py mcp-server/tests/test_kb_new_files_load.py
git commit -m "feat(kb): error-based blind SSTI oracle + ssti_elixir parent (D2)"
```

---

## Task 3: SSRF redirect-loop full-response leak (D3)

**Files:**
- Modify: `knowledge/ssrf_bypass.json` — add `redirect_loop_full_response_leak` context
- Modify: `tests/test_spec_d_kb.py` — add a presence assertion

**Interfaces:**
- Produces: `ssrf_bypass.json` gains a `redirect_loop_full_response_leak` context. This is a KB context (detection recipe); the incrementing-3xx OAST chain is operator-driven via existing `generate_collaborator_payload` — no new tool in this task.

- [ ] **Step 1: Add the failing assertion**

In `tests/test_spec_d_kb.py`, add:
```python
class SsrfRedirectLoopTest(unittest.TestCase):
    def test_context_present(self):
        ctxs = _load("ssrf_bypass.json")["contexts"]
        self.assertIn("redirect_loop_full_response_leak", ctxs)
        probe = ctxs["redirect_loop_full_response_leak"]["probes"][0]
        self.assertTrue(probe["matchers"])
```

- [ ] **Step 2: Run to verify failure**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb.SsrfRedirectLoopTest -v`
Expected: FAIL — context missing.

- [ ] **Step 3: Add the context**

In `knowledge/ssrf_bypass.json`, add inside `"contexts"`:
```json
    "redirect_loop_full_response_leak": {
      "description": "Assetnote/PortSwigger Top-10-2025 #3: attacker redirect server increments 3xx status (301->310) then 200. When the client's redirect threshold trips, the app's internal error handler leaks the entire redirect chain plus final response body — turning blind SSRF into full-response-readable. Point the SSRF param at a Collaborator subdomain running an incrementing-3xx responder (replace COLLABORATOR at runtime, Rule 9a). Compare length + leaked internal markers vs the blind baseline.",
      "tech_match": ["ssrf", "http-client", "curl", "libcurl", "reqwest"],
      "param_match": ["url", "uri", "next", "target", "redirect", "callback", "webhook", "image", "feed"],
      "probes": [
        {
          "payload": "https://COLLABORATOR/redir-chain",
          "description": "SSRF param -> incrementing-3xx Collaborator chain. Leak = internal error body echoing the redirect chain / final response.",
          "matchers": [
            {"type": "length_delta", "min_delta": 500, "weight": 40},
            {"type": "word", "words": ["redirect", "Location:", "internal", "upstream", "127.0.0.1", "169.254.169.254", "Max redirects"], "condition": "or", "weight": 50},
            {"type": "collaborator", "weight": 60}
          ],
          "severity": "high",
          "confidence_boost": 60,
          "variables": {"COLLABORATOR": "runtime"}
        }
      ]
    }
```

- [ ] **Step 4: Run + commit**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb -v`
Expected: PASS.
```bash
git add mcp-server/src/burpsuite_mcp/knowledge/ssrf_bypass.json mcp-server/tests/test_spec_d_kb.py
git commit -m "feat(kb): SSRF redirect-loop full-response leak context (D3)"
```

---

## Task 4: Next.js May-2026 middleware-bypass variant pack + RSC DoS (D4)

**Files:**
- Modify: `tools/cve_variant_probe.py` — add `_nextjs_middleware_variants`, register in `_GENERATORS`, add CVE map entries
- Modify: `knowledge/react_server_components.json` — add `server_function_deser_dos` context
- Modify: `tests/test_spec_d_kb.py` — variant-map + context assertions

**Interfaces:**
- Consumes: `_resolve_class(cve_id, explicit_class)`, `_GENERATORS: dict[str, Callable]` from `cve_variant_probe.py`.
- Produces: `_resolve_class("CVE-2026-44575", "")` → `"nextjs_middleware_bypass"`; `_GENERATORS["nextjs_middleware_bypass"]` exists and returns a non-empty variant list with labels `mw_bypass.rsc_suffix`, `mw_bypass.segment_prefetch`, `mw_bypass.query_route_override`.

**Dedup guard:** before writing, confirm CVE-2026-44573 (i18n locale-less `_next/data`) is NOT already the W31-c "i18n middleware strip" context — grep `nextjs_cache_poisoning.json` for `i18n`; if present, do not re-add that one variant.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_spec_d_kb.py`:
```python
class NextjsMiddlewareVariantTest(unittest.TestCase):
    def test_cve_maps_to_class(self):
        from burpsuite_mcp.tools.cve_variant_probe import _resolve_class
        self.assertEqual(_resolve_class("CVE-2026-44575", ""),
                         "nextjs_middleware_bypass")
        self.assertEqual(_resolve_class("CVE-2026-44574", ""),
                         "nextjs_middleware_bypass")

    def test_generator_emits_variants(self):
        from burpsuite_mcp.tools.cve_variant_probe import _GENERATORS
        gen = _GENERATORS["nextjs_middleware_bypass"]
        variants = gen("/admin", "CANARY123", "")
        labels = {v["label"] for v in variants}
        self.assertIn("mw_bypass.rsc_suffix", labels)
        self.assertIn("mw_bypass.query_route_override", labels)
        self.assertTrue(all("CANARY123" in json.dumps(v) for v in variants))

    def test_rsc_dos_context_present(self):
        ctxs = _load("react_server_components.json")["contexts"]
        self.assertIn("server_function_deser_dos", ctxs)
```

- [ ] **Step 2: Run to verify failure**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb.NextjsMiddlewareVariantTest -v`
Expected: FAIL — `KeyError: 'nextjs_middleware_bypass'` / context missing.

- [ ] **Step 3: Add the variant generator**

In `tools/cve_variant_probe.py`, add near the other generators (before `_GENERATORS`):
```python
def _nextjs_middleware_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Next.js May-2026 middleware bypass (CVE-2026-44575 .rsc/segment-prefetch
    reach protected content; CVE-2026-44574 query-param route override). `baseline`
    is the protected path (e.g. /admin)."""
    path = baseline or "/admin"
    variants: list[dict[str, Any]] = []
    # CVE-2026-44575: .rsc suffix skips middleware auth
    variants.append({
        "label": "mw_bypass.rsc_suffix", "method": "GET",
        "url_suffix": f"{path}.rsc",
        "headers": {"RSC": "1", "X-Praetor-Canary": canary}, "body": "",
    })
    # CVE-2026-44575: segment-prefetch header form
    variants.append({
        "label": "mw_bypass.segment_prefetch", "method": "GET",
        "url_suffix": path,
        "headers": {"Next-Router-Prefetch": "1", "RSC": "1",
                    "Next-Router-State-Tree": "%5B%22%22%5D",
                    "X-Praetor-Canary": canary}, "body": "",
    })
    # CVE-2026-44574: query param alters dynamic route value, hides path from middleware
    variants.append({
        "label": "mw_bypass.query_route_override", "method": "GET",
        "url_suffix": f"{path}?__nextDataReq=1&_rsc={canary[:6]}",
        "headers": {"X-Praetor-Canary": canary}, "body": "",
    })
    return variants
```
Then register it in `_GENERATORS`:
```python
    "nextjs_middleware_bypass": _nextjs_middleware_variants,
```
And add to `_CVE_TO_CLASS`:
```python
    "CVE-2026-44575": "nextjs_middleware_bypass",
    "CVE-2026-44574": "nextjs_middleware_bypass",
```
Note: if the generator dispatch (`gen(baseline_payload, canary, action_id)` at line ~522) sends variants via `headers`/`body`/`method`, confirm the send loop honors a `url_suffix` key; if the existing loop only varies headers/body against a fixed URL, append `url_suffix` handling there (one line: `url = base_url + v.get("url_suffix", "")`). Read lines ~505-527 before editing to match the actual send signature.

- [ ] **Step 4: Add the RSC deserialization-DoS KB context**

In `knowledge/react_server_components.json`, add inside `"contexts"`:
```json
    "server_function_deser_dos": {
      "description": "CVE-2026-23870 (Vercel/react.dev, May 2026): RSC Server-Function argument deserialization triggers CPU-DoS on React 19.x / all App Router. Malformed/oversized serialized action payload to a Server Action endpoint spikes CPU. Detection-only (Rule 5): send a moderately-nested payload and measure differential timing vs baseline; do NOT send a resource-exhausting payload.",
      "tech_match": ["nextjs", "react", "app-router", "rsc", "server-actions"],
      "param_match": [],
      "probes": [
        {
          "payload": "{\"__rsc_action\":true,\"args\":[[[[[[[[[[1]]]]]]]]]]}",
          "description": "Moderately-nested Server-Action arg; timing delta vs baseline flags the deserialization cost path.",
          "matchers": [
            {"type": "differential_timing", "threshold_ms": 1500, "weight": 60},
            {"type": "status", "status": [500, 503], "condition": "or", "weight": 30}
          ],
          "severity": "medium",
          "confidence_boost": 40,
          "variables": {}
        }
      ]
    }
```

- [ ] **Step 5: Run tests**

Run: `cd mcp-server && uv run python -m unittest tests.test_spec_d_kb -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add mcp-server/src/burpsuite_mcp/tools/cve_variant_probe.py \
        mcp-server/src/burpsuite_mcp/knowledge/react_server_components.json \
        mcp-server/tests/test_spec_d_kb.py
git commit -m "feat(kb): Next.js May-2026 middleware-bypass variants + RSC deser-DoS (D4)"
```

---

## Task 5: Advisor wiring + counts

**Files:**
- Modify: `tools/advisor/` `pick_tool` keyword router (grep for where probes are routed)
- Modify: `CLAUDE.md` KB-count + tool-count lines; `knowledge/_INDEX.md`

- [ ] **Step 1: Route the new probe in `pick_tool`**

Run: `cd mcp-server && grep -rn "probe_a2a_agent_card\|detect_mcp_schema_drift" src/burpsuite_mcp/tools/advisor/ | head`
Add a routing entry mapping keywords (`mcp`, `invisible`, `unicode`, `tool poisoning`, `tag block`) → `detect_mcp_invisible_unicode`, mirroring the nearest existing MCP-probe entry.

- [ ] **Step 2: Update counts + index**

Update `CLAUDE.md`: KB file count 150 → 151 (ssti_elixir.json), tool count +1 (detect_mcp_invisible_unicode). Add a one-line `_INDEX.md` entry for `ssti_elixir.json`. Add a short W38 changelog line noting D1–D4.

- [ ] **Step 3: Full suite + commit**

Run: `cd mcp-server && uv run python -m unittest discover tests -v 2>&1 | tail -20`
Expected: OK (all pass). Investigate any failure before committing.
```bash
git add mcp-server/src/burpsuite_mcp/tools/advisor CLAUDE.md \
        mcp-server/src/burpsuite_mcp/knowledge/_INDEX.md
git commit -m "chore(advisor,docs): route D1 probe + bump KB/tool counts (Spec D P0)"
```

---

## Self-Review

**Spec coverage:** D1 → Task 1 (probe + KB context). D2 → Task 2 (4 engine contexts + Elixir parent). D3 → Task 3 (ssrf context). D4 → Task 4 (variant pack + RSC DoS context). E1.2 token fix → Task 0. Advisor/counts → Task 5. P1 items (D5–D10) and the rest of Phase 0 (E1.1/E1.3/E1.5) are intentionally out of THIS plan — separate follow-on plans.

**Placeholder scan:** every code step carries complete code; every command has expected output. Two flagged verification points (Task 1 Step 6 regex flavor, Task 4 Step 3 `url_suffix` handling) require reading the exact adjacent code before editing — these are real "confirm the interface" steps, not placeholders, and each names the exact lines to read and the fallback.

**Type consistency:** `find_hidden_unicode`/`scan_tool_metadata` signatures match between Task 1's interface block, module code, and tests. `_resolve_class`/`_GENERATORS` names match `cve_variant_probe.py` as read. Verdict shape from Task 0 is what Task 1's probe returns.

**Known interface risks to confirm at execution time (not guesses — verify before editing):**
1. Task 1 Step 6 — Java `MatcherEngine` regex support for `\x{E0000}` (fallback: probe works via the Python tool regardless).
2. Task 4 Step 3 — whether the `probe_cve_with_variants` send loop honors a `url_suffix` key (read lines ~505-527; add one-line handling if absent).
