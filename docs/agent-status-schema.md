# Agent Status Schema

Compact machine-readable status object that worker agents return as their **final
output**, so the orchestrator (`grow-agent`) can parse progress without scraping
prose. One JSON object, no surrounding markdown.

## Schema

```json
{
  "agent": "string",              // agent name, e.g. "vuln-scanner"
  "domain": "string",             // target domain (slug)
  "phase": "string",              // what this run did, e.g. "scan", "recon", "verify"
  "status": "running|done|blocked",
  "findings_confirmed": 0,        // int — confirmed findings this run
  "findings_suspected": 0,        // int — suspected (need more evidence)
  "coverage_note": "string",      // terse: what was covered / scope of the run
  "next_action": "string",        // recommended hand-off for the orchestrator
  "blockers": ["string"]          // empty unless status == "blocked"
}
```

## Field rules

- `status`:
  - `running` — partial result, work continues (long tasks / checkpoints).
  - `done` — run complete, findings finalized.
  - `blocked` — cannot proceed; `blockers[]` MUST be non-empty (e.g. out-of-scope,
    missing session, ≥2 auth states required, device unauthorized).
- `findings_confirmed` / `findings_suspected` are **counts**, not IDs. The detailed
  ID lists stay in each agent's existing `## Returns` block.
- Recon/analysis agents that don't produce findings report `0`/`0` and describe
  what they mapped in `coverage_note`.
- `next_action` is a single directive the orchestrator can act on
  (e.g. "dispatch finding-verifier on f-0012", "auth-tester needs a 2nd session").

## Example

```json
{"agent":"vuln-scanner","domain":"example.com","phase":"scan:sqli","status":"done","findings_confirmed":1,"findings_suspected":2,"coverage_note":"sqli across 6 (endpoint,param) tuples on /api/*","next_action":"dispatch finding-verifier on suspected f-0007,f-0008","blockers":[]}
```

This object is additive to each agent's `## Returns` contract — it is the last thing
the agent emits, not a replacement for the domain-specific return payload.
