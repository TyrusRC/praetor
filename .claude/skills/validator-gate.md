---
name: validator-gate
description: Before promoting a HIGH/CRITICAL finding to confirmed, run an independent clean-room replay (confirm_with_clean_room) to kill false positives — the XBOW/Strix second-pass pattern
---

# Validator Gate

The strongest false-positive control in modern agentic pentest tools (XBOW,
Strix) is an INDEPENDENT validator that re-executes the PoC before a finding is
trusted. Discovery pulls in heuristics and false leads; a separate replay from
clean state, checking for the originally-claimed markers, is what separates a
real bug from a lucky response. Praetor already ships this as a tool —
`confirm_with_clean_room` — this skill mandates WHEN to fire it.

## When it is REQUIRED (not optional)

Run the gate before `save_finding` sets `status='confirmed'` for:

- any HIGH or CRITICAL candidate,
- any injection-reaching-a-sink class (sqli, rce, ssti, cmdi, ssrf-to-internal),
- any auth/authorization bypass (idor/bola/bfla, auth_bypass, jwt),
- any finding whose evidence is a single response (no baseline delta captured).

LOW/MEDIUM recon-shaped observations do not need it — they are leads, not
reports (Rule 29).

## The gate

```
confirm_with_clean_room(
    logger_index=<index of the confirming replay>,
    expected_markers=[<substrings that MUST appear if the bug is real>],
    replays=3,                 # timing/blind classes: >=5
    require_all_markers=True,
)
```

- Verdict CONFIRMED (markers returned on the clean replays) → proceed to
  `assess_finding` → `save_finding`.
- Verdict FAILED (markers absent) → do NOT save. The candidate goes to
  `save_target_notes`, not the board. A finding that only reproduced once is a
  false positive until proven otherwise.

## Rules

- The validator is INDEPENDENT of discovery: pass the confirming replay's
  logger index and the markers you expect, and let the replay speak. Do not
  hand-wave a CONFIRMED because "it worked earlier" — earlier is not now.
- `expected_markers` must be discriminating: a marker a plain 200 would also
  contain proves nothing (same bar as KB probe matchers).
- This gate is in addition to the Rule 10 replay, not a replacement. Rule 10
  proves the anomaly persists; the validator proves it from clean state with
  the exact markers a report will cite.
- Never skip the gate to save tokens on a HIGH/CRITICAL — a wrong CRITICAL
  costs the operator far more than one replay.
