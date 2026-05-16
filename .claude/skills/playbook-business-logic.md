---
name: playbook-business-logic
description: Find business-logic flaws — workflow bypass, state reuse, race-on-state, privilege boundary, multi-account collusion, price/quantity/coupon abuse. Highest-impact bugs in any engagement; auto_probe finds none of these.
---

# Business Logic Playbook

> **R12:** scope/safety/save-finding rules in `.claude/rules/hunting.md`. This skill is workflow only.

Business-logic bugs are the bugs that pay. `auto_probe` does not find them.
A reflected XSS pays $300. A coupon-stacking flaw that drains $40k of credit
pays $5k+. Read the app like an attacker, not a checklist.

Run AFTER `capture_business_context(domain, ...)`. The advisor and this skill
both consume the structured fields you set there.

---

## Phase 0 — Load context

Two reads, one budget item:

1. `get_business_context(domain)` → app_type, money_flow, sensitive_data,
   user_roles, kill_switches, key_workflows. If empty, **stop and run
   `capture_business_context` first** — every step below references it.
2. `load_target_intel(domain, "endpoints")` → endpoint list with risk scores.

Cross-reference: every `kill_switch` listed in business_context MUST map to
≥1 endpoint in the endpoint list. If you can't find the endpoint that
implements `delete_account`, you missed recon — go back to `discover_attack_surface`.

---

## Phase 1 — Map the state machine

For each `key_workflow` in business_context, draw the steps:

```
checkout: add_to_cart → review → pay → confirm
    └─ POST /cart/add        (param: item_id, qty)
    └─ POST /cart/review     (no params, reads session)
    └─ POST /pay             (param: payment_method, amount)
    └─ POST /confirm         (param: order_id)
```

For each step, capture (via Burp proxy history):
- HTTP method + path
- Required state (cookie, token, prior step's output)
- Server-side response (200 vs 302 vs structured JSON)
- Whether the step is **idempotent** (safe to repeat) or **mutating**

If you cannot draw this for the target's main flow, **stop and walk it
through the browser** (browser_crawl + browser_interact_all). Logic bugs
require knowing the intended flow.

---

## Phase 2 — Six attack patterns

Run each pattern against EACH workflow. One run per pattern, not one per parameter.

### A. Step skip

Hypothesis: backend trusts client to follow the order. Skip step N, send N+1
directly with state from N-1.

```
# Normal: cart → review → pay → confirm
# Test: cart → confirm   (skip review + pay)
session_request(s, "POST", "/confirm", json_body={"order_id": "<from cart response>"})
```

Confirmed = order created without payment. Save `vuln_type=workflow_bypass`.

### B. Step replay / step reorder

Send a step twice or out of order. Many flows assume each step runs once.

```
# Replay payment with same idempotency-key — does it charge again?
# Reorder: confirm BEFORE pay
```

Confirmed = duplicate charge / refund-without-pay / order-without-stock.

### C. State reuse (TOCTOU on stateful resources)

Use a token / nonce / coupon / one-time-link AFTER it should be invalid:
- expired password-reset token still works
- used coupon code still applies
- one-time download link still serves
- session-cookie that should have rotated still authenticates

```
# Step 1: claim coupon → returns success
# Step 2: claim same coupon again → expect rejection
# Step 3: race step 2 with `test_race_condition` — does the second request also succeed?
```

### D. Race on state (concurrency-bound logic)

The TOCTOU class. `test_race_condition` exists for exactly this. Run on
every state-changing endpoint where the `kill_switches` list intersects:

- coupon claim, vote, like, refund request, balance withdraw, role grant,
  password reset request, friend request, follow, comment delete

Confirmed = action runs MORE times than expected (3 coupons claimed by 1 user, balance debited 3×).

### E. Privilege boundary (BFLA + BOLA)

For each user_role pair `(low, high)`:
1. Authenticate as `low`. Capture every endpoint they hit (proxy history).
2. Re-issue the same requests with valid `low` cookies but path/params
   that target `high`-role resources.
3. Use `test_auth_matrix(endpoints, auth_states={low, high})` for batch.

BFLA bar: low-priv role calls a function (`/admin/users/delete`) and the
server processes it. BOLA bar: low-priv role accesses an object owned by
another user (or by `high`).

### F. Multi-account collusion / single-user-as-both-sides

Use two accounts. The bug exists when one user can be both **buyer + seller**,
**reporter + reportee**, **referrer + referree** in the same flow.

Concrete tests:
- self-referral bonus (refer yourself, claim bonus)
- buy-from-yourself fee bypass
- self-vote / self-like for ranking abuse
- escrow disputes where attacker is both parties

### G. Idempotency-key scope abuse

Stripe + many payment APIs require `Idempotency-Key`. The bug class:

- Same key reused across DIFFERENT customer accounts → response from first leaks to second
- Key scoped per (api_key) not per (api_key, customer) → cross-tenant data leak
- Server caches "successful" only — retry a failed key, race the retry, win it
- Empty / null / fixed key accepted (e.g. always `00000000`) → universal collision

Confirmed: same idempotency-key in two parallel customer contexts returns identical response containing the OTHER customer's resource id.

### H. Tenant / org boundary leak

Multi-tenant SaaS — the highest-paying class in B2B targets.

For each (tenant_a, tenant_b) pair you control:
1. Swap `tenant_id` / `org_id` / `workspace_id` in path / body / header / JWT claim
2. Email-domain inference: register `attacker@target.com` to auto-join target's tenant (Auth0 / Okta misconfig)
3. Invite link replay: tenant_a's invite link works in tenant_b's context
4. Cross-tenant search: `?q=<other-tenant-name>` reveals foreign-tenant data
5. Tenant ID enumeration: sequential / predictable id space
6. Shared resource references: file_id / asset_id without tenant scope check

Confirmed: read or modify another tenant's resource with attacker-tenant creds. CRITICAL per Phase 4 (money + sensitive_data multipliers stack).

### I. Entitlement / subscription state confusion

When `money_flow=subscriptions`:

- Upgrade-without-pay: `PATCH /subscription {"tier":"premium"}` without payment confirmation
- Downgrade-but-keep-features: downgrade to free; cached entitlement still grants premium
- Refund-without-revoke: refund issued; entitlement flag never cleared
- Trial-stacking: new accounts share one payment method, each gets free trial → unlimited
- Coupon-after-checkout: apply coupon AFTER order completes → refund "discount difference"
- Subscription pause + use: pause subscription; features active during pause window
- Lifetime entitlement transfer: gift "lifetime premium" to victim, revoke ownership; both stay entitled
- Cancel-during-billing-cycle: cancel right after charge; refund issued but billing-cycle features still active

### J. Identity normalization confusion

Same identity represented differently across systems:

- Email case: `Alice@x.tld` vs `alice@x.tld` — login accepts either while registration created only one
- Unicode normalization: `аdmin@x.tld` (Cyrillic а) vs `admin@x.tld` — IDN check passes, looks identical
- Plus-addressing: `admin+evil@x.tld` registers separate; normalizes to `admin@x.tld` in some flows
- Punycode: `аdmin@xn--target-tld` collides with real admin
- Trailing whitespace / zero-width: `admin​@x.tld` strips in one system, persists in another
- Phone: `+1-555-1234` vs `15551234` vs `+15551234` — same number, three users
- Account merge: register with victim's email + OAuth → backend merges accounts because email matches → attacker gets victim's data

Confirmed: attacker-controlled identity grants access intended for victim's identity (or vice versa). HIGH-CRITICAL by what the merged account can do.

---

## Phase 3 — Money / quantity / coupon-class manipulation

When `money_flow != "none"`, also run these:

| Test | Payload | Expected if vulnerable |
|---|---|---|
| Negative quantity | `qty=-1` on cart-add | Negative balance / refund |
| Negative price | `price=-100` (mass-assignment style) | Refund issued |
| Zero/decimal manipulation | `price=0.001` or `price=0` | Order at $0 |
| Type confusion | `qty=[1,2,3]`, `qty="1; 1=1"`, `qty=true` | Server crashes / coerces unsafely |
| Currency mismatch | `currency=BTC` when only USD supported | Conversion at attacker rate |
| Decimal overflow | `qty=99999999999.99` | Integer overflow / float precision loss |
| Coupon stacking | apply 2+ coupons in one order, or apply same coupon to many orders | Discount > intended |
| Precision diff | charge 1 cent on 1M items via float rounding | 1M cents drained |

Save as `vuln_type=business_logic` with concrete impact in dollars/units.

---

## Phase 4 — Kill-switch tests

For every entry in `kill_switches` (e.g. `delete_account`,
`transfer_funds`, `create_api_key`, `rotate_password`, `export_data`):

1. Verify the action runs at all (with valid auth).
2. CSRF: does it require a token? Replay without it.
3. Rate-limit: how many can be triggered in 60s? (use `test_rate_limit`)
4. Multi-step requirement: is there a confirmation step? (skippable per pattern A)
5. Privilege: does a low-priv role have access? (per pattern E)

Kill-switches are **always reportable** even when the standalone class is in
NEVER SUBMIT — the impact context lifts them. Use `chain_with` to anchor.

---

## Phase 5 — Save with business impact in the description

When you find a business-logic flaw:

```python
save_finding(
    title="Coupon stacking on /api/checkout allows arbitrary discount",
    vuln_type="business_logic",
    severity="HIGH",                 # operator-locked; advisor will infer too
    endpoint="POST /api/checkout",
    parameter="coupon_codes",
    evidence_text="Order #12345 at $0.00 after applying 5 stacked coupons "
                  "(50% + 50% + 50% + 50% + 50% — server multiplies, doesn't cap). "
                  "Reproduced 3x; logger_index=247,251,254.",
    evidence={"logger_index": 254},
    description=(
        "Backend applies coupon discount multiplicatively without capping. "
        "Attacker can reduce any order to $0 by submitting >=5 coupons. "
        "Verified across 3 distinct coupon codes; same flaw applies to "
        "promo + loyalty + employee discount fields. "
        "Estimated revenue impact: any user can checkout at zero cost; "
        "abusing 100 orders/day at avg $50 = $5k/day loss."
    ),
    domain=domain,
    confidence=0.95,
    status="confirmed",
)
```

The description should answer:
- **What** — bug class in one sentence
- **How** — exploit path (steps + payloads + reproductions)
- **Impact** — concrete dollars/users/data, not "potential abuse"
- **Why now** — why is this exploitable today (deployed, no rate limit, etc.)

---

## Quick checklist (run this before declaring "no business logic bugs")

- [ ] capture_business_context filled in (run get_business_context to verify)
- [ ] Every `key_workflow` walked end-to-end in browser proxy history
- [ ] Step-skip tested on at least the highest-value workflow (checkout, signup, password-reset)
- [ ] Step-replay / state-reuse tested on coupons, tokens, one-time links
- [ ] `test_race_condition` run on every endpoint touching `kill_switches`
- [ ] `test_auth_matrix` run across every (low, high) user_role pair
- [ ] Multi-account collusion tested (self-referral / self-buy-sell / self-vote)
- [ ] Negative + zero + type-confused values on every quantity/price/qty parameter
- [ ] Each `kill_switch` rate-limit measured
- [ ] G — Idempotency-key scope verified per-(account, key)
- [ ] H — Tenant / org boundary tested across (tenant_a, tenant_b) pairs
- [ ] I — Subscription / entitlement state confusion (upgrade-without-pay, refund-revoke, trial-stack)
- [ ] J — Identity normalization tested (email case / Unicode / plus / phone / merge)

If 8/9 boxes are checked and there are no findings, the target is genuinely
hardened against logic abuse — that itself is unusual and worth a one-line
note in `save_target_notes` for next session.

---

## Why this skill exists

The default Claude reflex on business-logic is to write a one-line "consider
testing for race conditions" and move on. That misses every bug that pays.
The bar is: **proof that the operator can lose money/data/control**, not
"theoretically a developer could have made a mistake".

Open this skill at engagement start. Re-read it after every confirmed
finding so you do not pivot away from logic too early.
