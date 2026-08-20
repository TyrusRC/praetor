"""Vuln-class orchestrators where no good third-party covers the surface.

Each tool sends multiple targeted probes through Burp in one call and
aggregates the result into a single verdict. Routes via /api/http/curl so
every request lands in Logger with a real history_index — citable as
evidence in save_finding.

Built natively (not as a third-party wrapper) because:
- CSRF: no maintained dedicated tool (CSRFTester is from 2008; Burp Pro has it
  but no programmatic API for the matrix tests)
- SSRF: nuclei has templates but no orchestrator; sqlmap-style coverage absent
- XXE: nuclei has a few templates; manual is the norm
- WebSocket: zero dedicated WS auth/origin scanners
- Prototype Pollution: PPScan exists for client-side; server-side detection
  has no good tool
- SSTI: tplmap is unmaintained Python2; SSTImap (vladko312 fork) is the active
  reference but spawning a subprocess breaks our `logger_index` chain. We
  encode its engine catalog + multi-phase detection logic natively against
  our knowledge base instead.

For SQLi / XSS / Command Injection use the established third-party wrappers —
run_sqlmap, run_dalfox, run_commix. They cover deeper than any native
orchestrator could.
"""

from mcp.server.fastmcp import FastMCP

from . import (
    test_csrf as _test_csrf,
    test_ssrf as _test_ssrf,
    test_ssti as _test_ssti,
    test_xxe as _test_xxe,
    test_websocket as _test_websocket,
    test_prototype_pollution as _test_pp,
)


def register(mcp: FastMCP):
    _test_csrf.register(mcp)
    _test_ssrf.register(mcp)
    _test_ssti.register(mcp)
    _test_xxe.register(mcp)
    _test_websocket.register(mcp)
    _test_pp.register(mcp)
