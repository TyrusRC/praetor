"""capture_business_context — persist structured app/threat-model context.

Writes into .burp-intel/<domain>/profile.json under `business_context` so the
advisor (assess.py) auto-loads it on every gate call. Operator runs this once
per engagement; assess_finding boosts impact for matches between vuln class
and business context (e.g. SQLi on banking, IDOR on multi-tenant SaaS).

Adaptive shape: known fields (app_type, money_flow, sensitive_data, user_roles,
kill_switches, key_workflows, threat_actors, notes) plus arbitrary extras the
operator chooses to record. Extras are persisted but not consumed by the gate.
"""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ._internals import _atomic_write_json, _ensure_dir, _intel_path


KNOWN_APP_TYPES = (
    "ecommerce", "banking", "fintech", "healthcare", "saas", "social",
    "government", "gaming", "content", "communication", "infrastructure",
    "crypto", "payment", "education", "marketplace", "iot",
)

KNOWN_SENSITIVE_DATA = (
    "pii", "pci", "phi", "financial", "credentials", "intellectual_property",
    "government", "biometric", "location", "minor_data", "none",
)


def register(mcp: FastMCP):

    @mcp.tool()
    async def capture_business_context(
        domain: str,
        app_type: str = "",
        money_flow: str = "",
        sensitive_data: list[str] | None = None,
        user_roles: list[str] | None = None,
        kill_switches: list[str] | None = None,
        key_workflows: list[dict] | None = None,
        threat_actors: list[str] | None = None,
        notes: str = "",
        extras: dict | None = None,
    ) -> str:
        """Persist structured business context for the target. Run ONCE at engagement start; assess_finding auto-loads it from profile.json thereafter.

        Args:
            domain: Target domain.
            app_type: ecommerce/banking/fintech/healthcare/saas/social/government/gaming/content/communication/infrastructure/crypto/payment/education/marketplace/iot. Drives the assess impact multiplier.
            money_flow: Free-text money movement (payments/subscriptions/payouts/...). Operator-facing, not scored.
            sensitive_data: Data classes touched (pii/pci/phi/financial/credentials/ip/government/biometric/location/minor_data/none).
            user_roles: Roles in the system, e.g. ['admin','merchant','customer','support']. Drives cross-role authz tests.
            kill_switches: High-impact actions (delete_account/transfer_funds/create_api_key/rotate_password/export_data).
            key_workflows: Workflow dicts {'name', 'steps':[...]} for workflow-bypass testing.
            threat_actors: competitor/criminal/nation_state/insider/automated_scanner. Sets report tone.
            notes: Freeform paragraph for anything the structured fields missed.
            extras: Free-form dict persisted as-is.
        """
        if not domain:
            return "Error: domain is required."

        # Normalize lowercased fields where the gate expects lowercased lookups
        bc: dict = {
            "app_type": (app_type or "").strip().lower(),
            "money_flow": (money_flow or "").strip(),
            "sensitive_data": [s.strip().lower() for s in (sensitive_data or []) if s.strip()],
            "user_roles": [r.strip() for r in (user_roles or []) if r.strip()],
            "kill_switches": [k.strip() for k in (kill_switches or []) if k.strip()],
            "key_workflows": list(key_workflows or []),
            "threat_actors": [t.strip().lower() for t in (threat_actors or []) if t.strip()],
            "notes": notes.strip(),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        if extras and isinstance(extras, dict):
            bc["extras"] = extras

        # Load existing profile (or start a new one) and merge.
        profile_path = _ensure_dir(domain) / "profile.json"
        profile: dict = {}
        if profile_path.exists():
            try:
                profile = json.loads(profile_path.read_text())
            except (json.JSONDecodeError, OSError):
                profile = {}

        profile["business_context"] = bc
        profile["last_modified"] = bc["captured_at"]
        _atomic_write_json(profile_path, profile)

        # Build a compact echo for the operator to verify what was captured.
        warnings: list[str] = []
        if bc["app_type"] and bc["app_type"] not in KNOWN_APP_TYPES:
            warnings.append(
                f"app_type={bc['app_type']!r} is non-canonical — gate match still works "
                f"by substring, but a known value gets the strongest impact boost. "
                f"Known: {', '.join(KNOWN_APP_TYPES)}"
            )
        unknown_data = [s for s in bc["sensitive_data"] if s not in KNOWN_SENSITIVE_DATA]
        if unknown_data:
            warnings.append(
                f"sensitive_data has non-canonical entries: {unknown_data}. "
                f"Known: {', '.join(KNOWN_SENSITIVE_DATA)}"
            )

        lines = [
            f"Business context captured for {domain}",
            f"  app_type:       {bc['app_type'] or '(none)'}",
            f"  money_flow:     {bc['money_flow'] or '(none)'}",
            f"  sensitive_data: {', '.join(bc['sensitive_data']) or '(none)'}",
            f"  user_roles:     {', '.join(bc['user_roles']) or '(none)'}",
            f"  kill_switches:  {', '.join(bc['kill_switches']) or '(none)'}",
            f"  workflows:      {len(bc['key_workflows'])} captured",
            f"  threat_actors:  {', '.join(bc['threat_actors']) or '(none)'}",
            "",
            "assess_finding will auto-load this on every gate call — no need to "
            "re-pass business_context per call.",
        ]
        if warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in warnings:
                lines.append(f"  - {w}")
        return "\n".join(lines)

    @mcp.tool()
    async def get_business_context(domain: str) -> str:
        """Return the captured business context for a domain (or empty if none).

        Args:
            domain: Target domain
        """
        if not domain:
            return "Error: domain is required."
        profile_path = _intel_path(domain) / "profile.json"
        if not profile_path.exists():
            return f"No profile.json for {domain}. Run capture_business_context() to set one."
        try:
            profile = json.loads(profile_path.read_text())
        except (json.JSONDecodeError, OSError):
            return f"profile.json for {domain} is corrupted."
        bc = profile.get("business_context")
        if not bc:
            return (
                f"No business_context captured for {domain}. "
                f"Run capture_business_context(domain='{domain}', app_type='...', "
                f"sensitive_data=[...], kill_switches=[...]) to set one."
            )
        return json.dumps(bc, indent=2)
