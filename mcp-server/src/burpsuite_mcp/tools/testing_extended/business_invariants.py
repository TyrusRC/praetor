"""infer_business_invariants — synthesize multi-step business-logic tests (W7, T10).

Senior-engineer move: standalone probe tools find pattern bugs; business logic
bugs live in the *invariants* a system assumes. This tool ingests:

  1. parse_api_schema output (OpenAPI / Swagger / Postman) — if available.
  2. Proxy history endpoint shape — if domain has captured traffic.
  3. Tech stack hints from .burp-intel/<domain>/profile.json.

…and emits ranked **business invariants** plus proposed tests:
  - state-machine ordering invariants (must follow A → B → C)
  - price/quantity arithmetic invariants (total = sum * qty)
  - resource-ownership invariants (this ID belongs to this principal)
  - rate / quota invariants (N requests per window)
  - one-time-action invariants (coupon, password reset, refund)
  - idempotency invariants (same key → same outcome)

Each invariant comes with a hypothesised attack and the recommended Praetor
tool to fire (run_flow / probe_workflow_reorder / probe_idempotency_key /
test_race_condition / probe_line_item_mutation / etc.).

Returns a structured plan, NOT execution. Operator approves then dispatches.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized


_STATE_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "checkout_flow",
        "needles": ["/cart", "/checkout", "/payment", "/confirm", "/place-order"],
        "invariant": "checkout must be confirmed after payment, not before",
        "test": "probe_workflow_reorder (skip /payment, jump to /confirm)",
        "tool": "probe_workflow_reorder",
        "severity": "high",
    },
    {
        "name": "password_reset",
        "needles": ["/forgot", "/reset", "/password", "/recover"],
        "invariant": "reset token is one-use, time-bound, principal-bound",
        "test": "replay reset URL after consumption; replay across principals",
        "tool": "analyze_reset_tokens",
        "severity": "critical",
    },
    {
        "name": "mfa_step_up",
        "needles": ["/mfa", "/2fa", "/totp", "/verify"],
        "invariant": "all sensitive actions require fresh MFA when MFA enabled",
        "test": "skip MFA step, direct-access sensitive endpoint",
        "tool": "test_mfa_bypass",
        "severity": "critical",
    },
    {
        "name": "coupon_promo",
        "needles": ["/coupon", "/promo", "/discount", "/voucher", "/redeem"],
        "invariant": "coupon code is one-use per account / one-use globally per spec",
        "test": "race-apply same coupon N times in burst",
        "tool": "test_race_condition",
        "severity": "high",
    },
    {
        "name": "subscription_billing",
        "needles": ["/subscribe", "/plan", "/upgrade", "/downgrade", "/cancel", "/refund"],
        "invariant": "downgrade applies post-period; refund + upgrade is single transaction",
        "test": "race cancel + new subscription; refund same order twice",
        "tool": "probe_workflow_reorder",
        "severity": "high",
    },
    {
        "name": "follow_friend",
        "needles": ["/follow", "/friend", "/block", "/connect", "/invite"],
        "invariant": "block/follow are mutually exclusive; counter increments are atomic",
        "test": "race follow + block; race follow + follow (duplicate counter increment)",
        "tool": "test_race_condition",
        "severity": "medium",
    },
    {
        "name": "transfer_funds",
        "needles": ["/transfer", "/withdraw", "/payout", "/send", "/payment"],
        "invariant": "balance decremented before fund delivery; idempotency key one-shot",
        "test": "race transfer X N times; reuse idempotency_key with different body",
        "tool": "probe_idempotency_key",
        "severity": "critical",
    },
]

_PRICE_KEYS = {"price", "amount", "total", "subtotal", "cost", "qty", "quantity", "tax", "fee", "shipping", "currency"}
_OWNERSHIP_KEYS = {"user_id", "userid", "account_id", "owner_id", "tenant_id", "org_id", "workspace_id", "project_id"}
_ID_KEYS = {"id", "uid", "pid", "order_id", "invoice_id", "ticket_id", "doc_id", "item_id", "product_id"}
_IDEMPOTENCY_KEYS = {"idempotency_key", "request_id", "client_token", "transaction_id"}


def _scan_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match endpoints against state patterns + parameter heuristics."""
    invariants: list[dict[str, Any]] = []
    if not endpoints:
        return invariants

    paths_by_pattern: dict[str, list[str]] = {p["name"]: [] for p in _STATE_PATTERNS}
    for ep in endpoints:
        url = (ep.get("url") or ep.get("path") or "").lower()
        params = {p.lower() for p in (ep.get("params") or [])}
        body_keys = {k.lower() for k in (ep.get("body_keys") or [])}
        for pattern in _STATE_PATTERNS:
            if any(n in url for n in pattern["needles"]):
                paths_by_pattern[pattern["name"]].append(ep.get("url") or ep.get("path") or "")

        all_keys = params | body_keys
        if _PRICE_KEYS & all_keys:
            invariants.append({
                "category": "price_arithmetic",
                "endpoint": ep.get("url") or ep.get("path"),
                "invariant": "total = sum(item.price * item.qty) + tax + shipping - discount",
                "test": "line-item mutation: tamper qty/price; observe whether server recomputes total",
                "tool": "probe_line_item_mutation",
                "severity": "high",
                "confidence": 0.7,
            })
            invariants.append({
                "category": "float_rounding",
                "endpoint": ep.get("url") or ep.get("path"),
                "invariant": "amount * unit_price rounded consistently (banker's rounding vs floor)",
                "test": "probe IEEE-754 edge cases: 0.1*3, 0.2+0.1, max double, negative zero",
                "tool": "probe_float_decimal_rounding",
                "severity": "medium",
                "confidence": 0.6,
            })

        if _OWNERSHIP_KEYS & all_keys or any(k in url for k in ("/users/", "/accounts/", "/orgs/")):
            invariants.append({
                "category": "resource_ownership",
                "endpoint": ep.get("url") or ep.get("path"),
                "invariant": "principal == resource.owner (BFLA)",
                "test": "cross-principal access — fetch with attacker-session, ID owned by victim",
                "tool": "test_auth_matrix",
                "severity": "high",
                "confidence": 0.8,
            })

        if _ID_KEYS & all_keys:
            invariants.append({
                "category": "id_enumeration",
                "endpoint": ep.get("url") or ep.get("path"),
                "invariant": "IDs not sequential / not predictable",
                "test": "probe N adjacent IDs; observe sparsity + auth boundary",
                "tool": "probe_id_monotonic",
                "severity": "high",
                "confidence": 0.7,
            })

        if _IDEMPOTENCY_KEYS & all_keys:
            invariants.append({
                "category": "idempotency",
                "endpoint": ep.get("url") or ep.get("path"),
                "invariant": "same idempotency_key → same outcome; key scoped to principal",
                "test": "reuse key with mutated body; reuse key across principals",
                "tool": "probe_idempotency_key",
                "severity": "high",
                "confidence": 0.8,
            })

    for pattern in _STATE_PATTERNS:
        steps = paths_by_pattern[pattern["name"]]
        if len(steps) >= 2:
            invariants.append({
                "category": "state_machine",
                "flow": pattern["name"],
                "steps": steps[:6],
                "invariant": pattern["invariant"],
                "test": pattern["test"],
                "tool": pattern["tool"],
                "severity": pattern["severity"],
                "confidence": 0.6 + 0.1 * min(len(steps) - 2, 3),
            })
    return invariants


def _load_profile(domain: str) -> dict[str, Any]:
    path = _intel_dir() / _sanitized(domain) / "profile.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _load_endpoints(domain: str) -> list[dict[str, Any]]:
    """Pull from endpoints.json (saved by recon/save_target_intel) or proxy history."""
    path = _intel_dir() / _sanitized(domain) / "endpoints.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    return data.get("endpoints") or []


def _dedupe(invariants: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for inv in invariants:
        key = (inv.get("category"), inv.get("endpoint") or inv.get("flow"), inv.get("invariant"))
        if key in seen:
            continue
        seen.add(key)
        out.append(inv)
    return out


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def infer_business_invariants(
        domain: str,
        api_schema_endpoints: list[dict] | None = None,
        max_invariants: int = 30,
        seed_matrix: bool = False,
    ) -> dict:
        """Walk discovered endpoints + parameters → propose business-logic invariants to test.

        Reads endpoints from `.burp-intel/<domain>/endpoints.json` (saved by
        save_target_intel) and, optionally, `api_schema_endpoints` if you've
        just run `parse_api_schema`. Returns ranked invariants + the exact
        Praetor tool to fire for each. This is synthesis, not execution.

        Args:
            domain: target domain.
            api_schema_endpoints: optional endpoint list from parse_api_schema.
                Shape: [{url|path, method, params?, body_keys?}, ...].
            max_invariants: cap on returned invariants (default 30).
            seed_matrix: when True, write the proposed invariants into the
                business-logic testcase matrix as untested checklist rows
                (feeds the W36-P1 completion gate). Existing/tested rows are
                preserved. Adds `matrix_seeded`/`matrix_skipped` to the result.
        """
        endpoints: list[dict[str, Any]] = []
        endpoints.extend(api_schema_endpoints or [])
        endpoints.extend(_load_endpoints(domain))

        if not endpoints:
            return {
                "domain": domain,
                "invariants": [],
                "note": (
                    "no endpoints — run discover_attack_surface + save_target_intel, "
                    "or pass api_schema_endpoints from parse_api_schema."
                ),
            }

        invariants = _scan_endpoints(endpoints)
        invariants = _dedupe(invariants)
        severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        invariants.sort(
            key=lambda i: (severity_rank.get(i.get("severity", "low"), 0),
                           float(i.get("confidence", 0.5))),
            reverse=True,
        )

        profile = _load_profile(domain)
        ranked = invariants[:max_invariants]
        result = {
            "domain": domain,
            "endpoints_scanned": len(endpoints),
            "tech_stack": profile.get("tech_stack") or profile.get("technologies"),
            "invariants": ranked,
            "total_proposed": len(invariants),
        }
        if seed_matrix:
            # Bridge propose → gate: write the ranked proposals as untested
            # checklist rows. Lazy import keeps report/ off this module's
            # import path (no cycle).
            from burpsuite_mcp.tools.report.business_logic_gate import seed_matrix as _seed
            seeded = _seed(domain, ranked)
            result["matrix_seeded"] = seeded["seeded"]
            result["matrix_skipped"] = seeded["skipped"]
            result["matrix_total"] = seeded["total"]
        return result
