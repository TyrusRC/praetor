---
description: How to consume Praetor's VerdictResult schema returned by 52+ assessment tools, and how to wire new tools into the schema. Load when refactoring tool output, building agent loops, or reading a testing-tool response.
globs:
---

# VerdictResult Schema (W7 → W13)

52+ assessment tools now return a structured `dict` instead of a prose string, so the orchestrator can pipe results into `assess_finding` without re-parsing. The schema is stable and operator-readable; raw text is preserved as `human_summary` for legacy consumers.

## Shape

```json
{
  "verdict": "CONFIRMED | SUSPECTED | FAILED | ERROR",
  "confidence": 0.0..1.0,
  "evidence_summary": "one-line summary the orchestrator can quote",
  "logger_indices": [42, 43, ...],
  "proxy_indices": [],
  "collaborator_interactions": ["abc.oastify.com"],
  "reproductions": [{"logger_index": ..., "elapsed_ms": ..., "status_code": ...}, ...],
  "vuln_type": "ssrf | idor | csrf | ...",
  "details": {...},
  "human_summary": "...legacy pretty text..."
}
```

## Semantics

- **CONFIRMED** — replay-based proof OR matcher fired on a class-defining marker. Confidence ≥ 0.70. Safe to feed directly into `assess_finding` evidence.
- **SUSPECTED** — strong anomaly vs baseline, but missing one of: replay-stable, executable context, OOB confirmation. Confidence 0.45–0.69. Operator should escalate (Collaborator poll, manual confirm) before save.
- **FAILED** — probe ran, no anomaly. Tool's contract is "I tested this; nothing found." Treat as covered-negative in `coverage.json`.
- **ERROR** — probe could not run (scope, network, missing dep). Do NOT mark as covered. Operator must fix the precondition.

## Confidence floor

The Q5 evidence gate in `assess_finding` floors at ~0.45. The mapping `verdict_from_tally(hits)` (in `_verdict.py`) implements:

| hits | verdict   | confidence |
|------|-----------|------------|
| 0    | FAILED    | 0.10       |
| 1    | SUSPECTED | 0.55       |
| ≥2   | CONFIRMED | 0.85       |

This is the canonical mapping for tools whose verdict is "did any of N probe axes succeed". Tools with non-tally logic (e.g. CONFIRMED only when a CRITICAL subset is hit) call `make_verdict` directly.

## Authoring a new tool

```python
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict, verdict_from_tally

@mcp.tool()
async def my_probe(...) -> dict:
    """..."""
    if not preconditions_met:
        return error_verdict("missing X", vuln_type="my_class")

    # ... do work ...
    hits = count_positive_hits()
    lines = build_human_summary()

    verdict, confidence = verdict_from_tally(hits)
    return make_verdict(
        verdict, confidence,
        f"summary of finding shape ({hits} hits)",
        vuln_type="my_class",
        logger_indices=indices,
        details={"key": "value"},
        summary="\n".join(lines),
    )
```

## Consuming a verdict

```python
from burpsuite_mcp.tools.testing._verdict import is_actionable, to_assess_evidence

result = await test_ssrf(url="...", parameter="url")
if is_actionable(result):
    evidence = to_assess_evidence(result)
    assessment = await assess_finding(
        vuln_type=result["vuln_type"],
        evidence=str(evidence),
        endpoint=...,
        logger_index=result["logger_indices"][0] if result["logger_indices"] else -1,
    )
```

The pretty text still flows to the operator via `result["human_summary"]`.

## When NOT to return a verdict

- **UI / utility actions**: `send_to_comparer`, `send_to_organizer`, `annotate_request`, `match_replace`.
- **Recon / discovery aggregators**: `discover_attack_surface`, `full_recon`, `browser_crawl`.
- **External tool wrappers without parsing**: `run_nuclei`, `run_subfinder`, etc.

When in doubt: if the tool's contract is "did vuln class X manifest on target Y", it should return a VerdictResult. Otherwise string is fine.

## Coverage as of W15

**43 testing tools** return VerdictResult dict. All assessment-class tools converted. Remaining string-return tools fall into three intentional categories (see "When NOT to return a verdict"). See `MEMORY.md` `Praetor — W{N}` entries for the rolling count.

## Ref-only KB policy (W15 audit)

The following KBs are intentionally `_REFERENCE_ONLY` and will not be promoted to active auto_probe. Operator-driven payload guidance only.

| KB | Why ref-only |
|---|---|
| `captcha_bypass` | Human-driven; can't auto-probe |
| `ci_actions_injection` | Probed via poutine / octoscan binaries (W6 CI/CD wave) |
| `dependency_confusion` | Registry side-channel, not target HTTP |
| `desktop_electron` | Binary inspection via static-grep (W8) |
| `h2_continuation_flood` | DoS class — Rule 5 hard block |
| `http2_connect_portscan` | Needs raw H2 CONNECT transport |
| `http3_quic` | Needs raw QUIC transport |
| `kubernetes_exposed` | Network-level discovery; covered by W6 K8s tooling (kubescape / kube-hunter) |
| `race_condition` | Covered by dedicated `test_race_condition` / `probe_race_*` tools |
| `request_smuggling` | Covered by dedicated `test_request_smuggling` tool |
| `saml_xsw` | Operator-built XML signature payloads |
| `soapwn` | Needs attacker-hosted WSDL + XSD chain |
| `source_code_exposure` | Covered by `discover_common_files` |
| `tech_vulns` | CVE knowledge / W6 KEV-EPSS — not a probe set |
| `web_cache_poisoning_dos` | DoS class — Rule 5 hard block |
| `xs_leak` | Needs browser-side timing |
| `zip_slip` | Upload-then-trigger two-step extraction observation |

If a future operator asks "can we promote X?", consult this table first. Don't re-audit.

## Related

- `.claude/rules/hunting.md` Rule 22 — One smart tool call > five chatty ones. VerdictResult is the contract that lets a smart tool be smart.
- `.claude/skills/verify-finding.md` — Per-class evidence bars. The `verdict` field maps to those bars.
- `assess_finding(vuln_type, evidence, ...)` — Consumes the evidence summary that VerdictResult provides.
