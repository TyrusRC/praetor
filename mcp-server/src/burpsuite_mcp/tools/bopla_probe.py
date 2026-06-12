"""probe_bopla — Rapid7 InsightAppSec May 2026 (BOPLA matrix).

Broken Object Property Level Authorization. Distinct from BOLA (whole-object
authz) and mass assignment (write-side property overload):

  BOLA: user A can read user B's user object at all.
  Mass Assignment: user A can WRITE a property they shouldn't (e.g. is_admin).
  BOPLA: user A can READ a property they shouldn't see (e.g. user B's email),
         even though server enforces top-level object authz.

Mechanism: API returns a resource via a single endpoint; the server filters
WHICH resources to return based on caller but DOESN'T filter property
visibility per role. Operator runs the probe across ≥2 roles to surface
the matrix.

Strategy:
  1. For each session (role), fetch the same endpoint.
  2. JSON-decode each response and walk all keys (incl. nested).
  3. Build a per-property × per-role visibility matrix.
  4. CONFIRMED if any property is visible to a lower-trust role that
     should NOT see it (operator-supplied `restricted_fields`).
  5. SUSPECTED on inconsistent property visibility across roles even
     without explicit `restricted_fields` hint.

Returns VerdictResult.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_DEFAULT_RESTRICTED = (
    "email", "phone", "ssn", "tax_id", "credit_card", "card_number",
    "bank_account", "iban", "passport", "license_number", "address",
    "date_of_birth", "dob", "password", "password_hash", "salt",
    "api_key", "secret", "private_key", "session_id", "csrf_token",
    "role", "permissions", "scopes", "is_admin", "is_superuser",
    "tenant_id", "org_id", "account_id", "internal_id",
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_bopla(
        target_url: str,
        role_sessions: list[dict],
        method: str = "GET",
        restricted_fields: list[str] | None = None,
        json_body: dict | None = None,
    ) -> dict:
        """Probe Broken Object Property Level Authorization (BOPLA).

        Sends the same request as each role and diffs property-level
        visibility. CONFIRMED if a low-trust role sees properties that
        only a higher-trust role should see.

        Args:
            target_url: target endpoint URL.
            role_sessions: list of dicts: [{role: str, session: str,
                bearer: str (optional), trust_rank: int}, ...]. Higher
                trust_rank = more privileged. Need ≥2 entries.
            method: HTTP method (default GET).
            restricted_fields: property names that should ONLY be visible
                to the highest trust_rank. Default: common PII / auth /
                tenant fields.
            json_body: optional JSON body to send with each request
                (for POST / PUT).

        Returns: VerdictResult.
        """
        if not target_url:
            return error_verdict("target_url required", vuln_type="bopla")
        if not role_sessions or len(role_sessions) < 2:
            return error_verdict(
                "role_sessions: need ≥2 entries (low-trust + high-trust)",
                vuln_type="bopla",
            )

        restricted = list(restricted_fields or _DEFAULT_RESTRICTED)
        restricted_lc = {f.lower() for f in restricted}

        ranked = sorted(role_sessions, key=lambda r: r.get("trust_rank", 0))
        if any("trust_rank" not in r for r in ranked):
            return error_verdict(
                "each role_sessions entry needs `trust_rank` (int)",
                vuln_type="bopla",
            )

        reproductions: list[dict] = []
        logger_indices: list[int] = []
        per_role_properties: dict[str, set[str]] = {}

        for role_entry in ranked:
            role = role_entry.get("role") or f"trust{role_entry.get('trust_rank')}"
            resp = await _send(target_url, method, role_entry, json_body)
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            status = resp.get("status_code") or resp.get("status")
            body = resp.get("response_body") or ""
            props = _flat_keys(body)
            per_role_properties[role] = props
            reproductions.append({
                "role": role,
                "trust_rank": role_entry.get("trust_rank"),
                "status_code": status,
                "logger_index": li,
                "property_count": len(props),
                "properties_visible": sorted(props)[:60],
            })

        # Matrix: property → list of roles that see it
        all_props: set[str] = set().union(*per_role_properties.values())
        prop_matrix = {
            p: sorted(r for r, props in per_role_properties.items() if p in props)
            for p in all_props
        }

        # Find leaks: restricted prop visible to a non-top-rank role
        top_rank = ranked[-1].get("trust_rank")
        top_role = ranked[-1].get("role") or f"trust{top_rank}"
        leaks: list[dict] = []
        for p, roles_seeing in prop_matrix.items():
            if p.lower() not in restricted_lc:
                continue
            non_top = [r for r in roles_seeing if r != top_role]
            if non_top:
                leaks.append({
                    "property": p,
                    "leaked_to_roles": non_top,
                    "should_only_see": [top_role],
                })

        # Suspected: property visibility differs across roles without an
        # explicit restricted-fields hint.
        prop_visibility_delta = {
            p: roles for p, roles in prop_matrix.items()
            if len(roles) != len(ranked)
        }

        if leaks:
            return make_verdict(
                "CONFIRMED", 0.86,
                f"BOPLA confirmed — {len(leaks)} restricted property/properties "
                f"visible to non-privileged role(s). "
                f"First: `{leaks[0]['property']}` leaked to "
                f"{leaks[0]['leaked_to_roles']}.",
                vuln_type="bopla",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"leaks": leaks[:20],
                         "prop_matrix_size": len(all_props),
                         "roles_count": len(ranked)},
                summary=f"CONFIRMED BOPLA on {target_url} — "
                        f"{leaks[0]['property']} leaked",
            )

        if prop_visibility_delta:
            sample = dict(list(prop_visibility_delta.items())[:10])
            return make_verdict(
                "SUSPECTED", 0.55,
                f"Property-visibility delta across roles "
                f"({len(prop_visibility_delta)} props differ) — review whether "
                "non-top-rank roles should see any of the differing fields.",
                vuln_type="bopla",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"differing_properties": sample,
                         "differing_count": len(prop_visibility_delta)},
                summary=f"SUSPECTED BOPLA delta on {target_url}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"All {len(all_props)} properties consistent across "
            f"{len(ranked)} roles. No BOPLA delta.",
            vuln_type="bopla",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no BOPLA on {target_url}",
        )


# ----- Helpers -------------------------------------------------------------


def _flat_keys(body: str, prefix: str = "") -> set[str]:
    """Walk JSON body and return dotted key paths (e.g. user.email, items.0.price)."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return set()
    out: set[str] = set()
    _walk(obj, prefix, out, depth=0, max_depth=6)
    return out


def _walk(node, prefix: str, out: set[str], depth: int, max_depth: int) -> None:
    if depth > max_depth or len(out) > 500:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            ks = str(k)
            path = f"{prefix}.{ks}" if prefix else ks
            out.add(ks)  # also add unqualified key — primary BOPLA test
            out.add(path)
            _walk(v, path, out, depth + 1, max_depth)
    elif isinstance(node, list):
        for i, v in enumerate(node[:10]):
            path = f"{prefix}.{i}" if prefix else str(i)
            _walk(v, path, out, depth + 1, max_depth)


async def _send(url: str, method: str, role_entry: dict, json_body: dict | None) -> dict:
    session = role_entry.get("session", "")
    bearer = role_entry.get("bearer", "")
    headers: list[dict] = []
    if bearer:
        headers.append({"name": "Authorization", "value": f"Bearer {bearer}"})
    body: dict = {"method": method, "url": url, "headers": headers}
    if json_body is not None:
        body["json_body"] = json_body
    if session:
        body["session"] = session
        return await client.post("/api/session/request", json=body)
    return await client.post("/api/http/curl", json=body)
