---
name: cleanup-rollback
description: End-of-engagement reconciliation — before the final report, list every state-changing action from the operator log (test accounts, config changes, dropped files, background processes, listeners) and confirm each was reverted to baseline. Use when closing out an authorized engagement, or when asked "did we clean up".
---

# Cleanup / Rollback — Put Everything Back

Professional engagement hygiene: an authorized test that created state on a
target reverts that state before it closes. Same discipline as a physical
pentester re-locking every door they propped. This is a bookkeeping pass over
records of actions already taken — it plants and generates nothing.

## When to run

- **End of an authorized engagement, before the final report** (Phase 5 delivery).
- Whenever the operator asks "did we put everything back / clean up".
- Any red-team session that touched persistence, privilege escalation,
  execution, C2, or dropped a payload.

## The loop

1. `get_cleanup_checklist(domain)` — reads the operator log and returns the
   state-changing actions grouped into categories: **account** (test accounts /
   credential changes), **config** (registry / attribute / GPO changes),
   **file** (uploaded or dropped artifacts), **process** (services / scheduled
   tasks / spawned background processes), **listener** (relays / proxies /
   poisoning listeners). Read-only recon and credential dumps do not appear.
2. Work each `outstanding` item: perform the suggested reconciliation step
   (`suggested` field) against the recorded `where` / `command`.
3. `mark_cleanup_reconciled(domain, item_id, evidence="…")` — check it off,
   recording how it was reverted. `item_id` is the oplog id from the checklist.
   State persists in `.burp-intel/<domain>/network/cleanup.json`, so you can
   run the checklist across several calls without losing progress.
4. Re-run `get_cleanup_checklist(domain)` until `outstanding` is 0, or record
   the reason any item cannot be reverted.

## Reporting

- An **un-reconciled line is a note in the final report, not a hard block**.
  The tool never refuses anything — it tracks. If an artifact genuinely must
  stay (client asked to keep a test account for retest), leave it un-reconciled
  and note why in the report.
- List outstanding items in the deliverable's close-out / detection-and-hardening
  section so the client knows exactly what remains and where.

## Cross-references

- Operator log the checklist reads: `record_redteam_action` / `get_operator_log`
  (`.claude/skills/operational-discipline.md`).
- Engagement close-out phase: `.claude/skills/command-engagement.md` Phase 5.
