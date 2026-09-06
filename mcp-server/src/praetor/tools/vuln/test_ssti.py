r"""test_ssti — native SSTI detection orchestrator.

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

from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────────────────────────────────
# Engine catalog — distilled from SSTImap + our knowledge/ssti*.json files
# ─────────────────────────────────────────────────────────────────────────


from ._ssti_payloads import _POLYGLOT, _POLYGLOT_HINTS, _DISTINGUISHERS, _CAPABILITIES, _BLIND_SLEEPS  # noqa: F401 (re-export)
from ._ssti_helpers import _build_request, _send, _logger_index, _body  # noqa: F401 (re-export)
from ._test_ssti_impl import _run_test_ssti


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
    ) -> dict:
        """SSTImap-style native SSTI detection through Burp.

        Returns VerdictResult (W7 schema).

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
        return await _run_test_ssti(
            endpoint,
            parameter,
            method=method,
            session=session,
            blind=blind,
            blind_seconds=blind_seconds,
            engine_hint=engine_hint,
        )
