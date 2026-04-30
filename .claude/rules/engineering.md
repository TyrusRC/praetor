---
description: Always-active engineering rules for development, pentesting, bug bounty, and red team operations. Apply on every turn.
globs:
---

# Engineering Rules

These rules govern ALL work — code, config, pentest tool calls, payload crafting, report writing, bug bounty hunting, red team operations. No exceptions.

## 1. Think Before Acting

Don't assume. Don't hide confusion. Surface tradeoffs.

- State assumptions explicitly before implementing. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

**In pentesting/bug bounty:** if the target behavior is ambiguous (vuln or intended?), state the ambiguity and test both hypotheses rather than assuming.

**In red team:** identify the objective (data exfil, persistence, lateral movement) before picking tools. Wrong tool = detection.

## 2. Simplicity First

Minimum that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If 200 lines could be 50, rewrite it.

**In pentesting:** one smart tool call over five chatty ones. `smart_analyze` over 5 separate analysis calls. 3 targeted payloads over 20 spray payloads.

**In bug bounty:** one confirmed critical > ten unverified mediums. Depth over breadth. Prove impact, don't list anomalies.

**In red team:** minimum footprint. One clean exploit > noisy scanning. Stealth is a feature.

## 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

**When editing code:**
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

**When your changes create orphans:**
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

**The test:** every changed line traces directly to the user's request.

**In pentesting:** don't test endpoints outside the current objective. Don't re-test parameters already covered. Check `load_target_intel(domain, "coverage")` before probing.

**In red team:** every action should advance the kill chain. Recon that doesn't inform exploitation is wasted noise budget.

## 4. Goal-Driven Execution

Define success criteria. Loop until verified.

**Transform tasks into verifiable goals:**
- "Add validation" -> write tests for invalid inputs, then make them pass
- "Fix the bug" -> write a test that reproduces it, then make it pass
- "Test for SQLi" -> establish baseline, send probe, measure delta, verify with replay
- "Escalate to admin" -> identify privilege boundary, craft bypass, verify elevated access

**For multi-step tasks, state a brief plan:**
```
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require clarification — ask for it.

**In pentesting:** every probe has a hypothesis and a verification step. "I expect status 500 with SQL error" not "let me try some payloads and see what happens."

**In bug bounty:** the goal is a report with verified impact. Work backwards: what evidence does the triager need? Collect that evidence, then write.

**In red team:** the goal is the objective (flag, data, access). Every action either advances toward it or gathers intel for the next step. If you're stuck for 3 rounds, pivot.
