---
description: Smart move on the very first call against a target domain — session-start gate + recon + triage in 5 steps. Use as the literal first action when domain is identified.
globs:
---

# Smart Move — Fresh Target (Session Start)

Trigger: first identifiable domain in the session. Skipping this gate is the
top cause of duplicate work + missed chains (Rule 20a).

## The move (5 steps — fixed order)

```
1. intel = load_target_intel(domain='target.com', section='all')
2. fresh = check_target_freshness(domain='target.com', session=session_name)
3. (if intel empty OR fresh.profile == 'stale')
       check_scope('target.com')
       run_recon_phase('https://target.com')
       discover_attack_surface('target.com')
       save_target_intel(domain, 'profile', {...})
       save_target_intel(domain, 'endpoints', {...})
4. captured = get_proxy_history(host='target.com', limit=20)
5. for index in captured[:5]:
       plan = smart_request_triage(index)
       dispatch plan["attack_plan"][0]["suggested_call"]
```

That's it. Don't pre-test any vuln class before step 5 completes.

## What each step gives you

| Step | Cost | Yield |
|---|---|---|
| 1 | <1s read | Existing tech stack, auth model, findings list, scope rules |
| 2 | <1s read | Which intel sections are stale (target changed since last visit) |
| 3 | medium | Fresh attack surface: endpoints, params (risk-scored), JS files, common files, headers verdict |
| 4 | <1s read | Top-20 captured baselines for synthesis |
| 5 | per-index cheap | Priority-ordered attack_plan per entry — already routed |

## Stop conditions

- Step 1 returns non-empty intel + step 2 says FRESH → skip step 3 entirely. Step 4 + 5 still run.
- Step 3 returns 0 endpoints → target is a single-page or non-web — load `playbook-mobile-backend.md` or `desktop-electron.md`.
- Step 5 plan[0] verdict CONFIRMED on any entry → Rule 10 pipeline → save_finding before continuing.

## Rule references

- Rule 1 (scope check) — step 3 calls `check_scope` before any recon traffic.
- Rule 18 (annotate + organize) — every step-5 captured entry gets annotated by triage routing.
- Rule 20a (session-start recon gate) — this skill IS the implementation.
- Rule 21 (save progress at every checkpoint) — step 3 saves immediately.

## Anti-pattern

Don't call `quick_scan` first. Don't call `auto_probe` before recon
phase completes. Don't skip step 1 because "I remember this target" —
intel files decay; verify what changed.
