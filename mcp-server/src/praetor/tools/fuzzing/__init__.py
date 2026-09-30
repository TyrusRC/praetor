"""Fuzzing lane: structure-aware file-upload fuzzing + CVE-exploitability verdict.

Two co-operating features (Phase 1):
- `fuzz_upload` — black-box, structure-aware mutation-upload against an upload
  endpoint (format-aware seeds + dictionaries, mutate through Burp, classify
  parser anomalies vs a clean baseline). Universal; no local binary needed.
- `assess_cve_exploitability` — one-call "exploitable on THIS target" verdict
  over the existing CVE chain (map/lookup -> KEV/EPSS -> live precondition ->
  adapted BENIGN PoC).

Safety (HARD Rules 5-9): the deliverable is a crash / parser anomaly as the
PoC, never a weaponized shell. Campaigns are bounded + DoS-confirm-gated.
Submodules are imported lazily in register() so each verifies in isolation.
"""

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    from . import upload, cve_verdict

    upload.register(mcp)
    cve_verdict.register(mcp)
