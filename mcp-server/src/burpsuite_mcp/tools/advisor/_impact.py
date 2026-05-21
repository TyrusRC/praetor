"""Impact scoring + business-context boosts for assess_finding.

Runs AFTER the question loop. Mutates ctx.impact_boost / ctx.impact_notes.
These feed the suggested_confidence formula in _severity.py.

Reads .burp-intel/<domain>/profile.json (mtime-cached) for the structured
business_context dict captured by capture_business_context().
"""

import json
from pathlib import Path

from burpsuite_mcp import client
from ._context import AssessContext
from ..advisor_kb import AUTH_STATE_DEPENDENT


_profile_cache: dict[str, tuple[int, dict]] = {}


def _read_profile_cached(path: Path) -> dict:
    """mtime-keyed cache for .burp-intel/<domain>/profile.json."""
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return {}
    key = str(path)
    cached = _profile_cache.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    data = json.loads(path.read_text())
    _profile_cache[key] = (mtime, data)
    return data


_BIZ_MULTIPLIERS = {
    "banking": ("financial data at risk", 0.10),
    "fintech": ("financial data at risk", 0.10),
    "healthcare": ("PHI/PII exposure — HIPAA implications", 0.10),
    "government": ("citizen data / national security", 0.08),
    "ecommerce": ("payment data / PCI scope", 0.08),
    "payment": ("payment data / PCI scope", 0.08),
    "saas": ("multi-tenant data leakage risk", 0.06),
    "social": ("user PII / account takeover risk", 0.05),
    "crypto": ("financial loss / wallet compromise", 0.10),
}

_HIGH_IMPACT_COMBOS = {
    ("sqli", "banking"): "SQL injection on banking app = direct financial data access",
    ("sqli", "healthcare"): "SQL injection on healthcare = PHI breach",
    ("idor", "saas"): "IDOR on multi-tenant SaaS = cross-tenant data leak",
    ("idor", "ecommerce"): "IDOR on ecommerce = other users orders/payment data",
    ("ssrf", "cloud"): "SSRF on cloud-hosted = metadata credential theft",
    ("xss", "banking"): "XSS on banking = session hijack for financial access",
    ("auth_bypass", "payment"): "Auth bypass on payment = unauthorized transactions",
    ("rce", "production"): "RCE on production = full system compromise",
}

_BIZ_SENSITIVE_CLASSES = {
    "idor", "bfla", "business_logic", "mass_assignment",
    "broken_object_level_auth", "broken_function_level_auth",
    "excessive_data_exposure",
}

_HIGH_VALUE_DATA = {"pci", "phi", "financial", "credentials", "biometric"}

_ID_ENUM_SIGNALS = (
    "sequential", "predictable", "incrementing", "guessable",
    "auto-increment", "id enumeration", "fuzz id", "enumerate id",
    "same id space", "cross-app", "shared id",
)


async def apply_impact_scoring(ctx: AssessContext) -> None:
    """Populate ctx.impact_boost / ctx.impact_notes / ctx.biz_data /
    ctx.grey_box_active. Order matches the original assess_finding_impl."""

    # ── Auto-load business_context from profile.json ──
    if ctx.domain:
        try:
            from burpsuite_mcp.tools.intel import _intel_path
            profile_path = _intel_path(ctx.domain) / "profile.json"
            if profile_path.exists():
                profile = _read_profile_cached(profile_path)
                bc = profile.get("business_context") or {}
                if isinstance(bc, dict):
                    ctx.biz_data = bc
                    if not ctx.business_context:
                        ctx.business_context = bc.get("app_type", "") or ""
        except (json.JSONDecodeError, OSError):
            pass

    biz = ctx.business_context.lower() if ctx.business_context else ""
    env = ctx.environment.lower() if ctx.environment else ""

    # ── Biz-context multipliers ──
    for biz_key, (reason, boost) in _BIZ_MULTIPLIERS.items():
        if biz_key in biz:
            ctx.impact_boost += boost
            ctx.impact_notes.append(f"Business context ({biz_key}): {reason} (+{boost:.0%})")
            break

    # ── Environment context ──
    if "production" in env or "prod" in env:
        ctx.impact_boost += 0.05
        ctx.impact_notes.append("Production environment: live user impact (+5%)")
    elif "internal" in env:
        ctx.impact_boost -= 0.05
        ctx.impact_notes.append("Internal environment: reduced external exposure (-5%)")

    # ── Warn when biz-sensitive vuln class lacks business_context ──
    if (
        not ctx.biz_data
        and ctx.q2_class_root in _BIZ_SENSITIVE_CLASSES
        and ctx.domain
    ):
        ctx.impact_notes.append(
            f"WARNING: no business_context captured for {ctx.domain}. "
            f"{ctx.q2_class_root} impact scoring missing sensitive_data / kill_switches boost — "
            f"run capture_business_context(domain='{ctx.domain}', ...) before save_finding."
        )

    # ── Structured business_context consumers ──
    sensitive_data = ctx.biz_data.get("sensitive_data") or [] if ctx.biz_data else []
    matched_data = [d for d in sensitive_data if str(d).lower() in _HIGH_VALUE_DATA]
    if matched_data:
        ctx.impact_boost += 0.05
        ctx.impact_notes.append(
            f"Sensitive data class in scope ({', '.join(matched_data)}) (+5%)"
        )

    kill_switches = ctx.biz_data.get("kill_switches") or [] if ctx.biz_data else []
    if kill_switches:
        ep_compact = (
            (ctx.endpoint or "")
            .replace("/", "")
            .replace("_", "")
            .replace("-", "")
            .replace(" ", "")
            .lower()
        )
        vuln_compact = ctx.vuln_lower.replace("_", "").replace("-", "")
        for ks in kill_switches:
            ks_str = str(ks).strip()
            if not ks_str:
                continue
            ks_compact = (
                ks_str.replace("_", "").replace("-", "").replace(" ", "").lower()
            )
            if ks_compact and (ks_compact in ep_compact or ks_compact in vuln_compact):
                ctx.impact_boost += 0.10
                ctx.impact_notes.append(
                    f"Endpoint/vuln aligns with captured kill-switch '{ks}' (+10%)"
                )
                break

    # ── Grey-box mode boost when session is authenticated ──
    if ctx.session_name:
        try:
            sess_list = await client.get("/api/session/list")
            if isinstance(sess_list, dict) and "error" not in sess_list:
                for s in sess_list.get("sessions", []) or []:
                    if not isinstance(s, dict):
                        continue
                    if s.get("name") != ctx.session_name:
                        continue
                    cookie_count = s.get("cookie_count", 0) or 0
                    has_auth = bool(s.get("has_auth_header") or s.get("auth_header"))
                    if cookie_count > 0 or has_auth:
                        ctx.grey_box_active = True
                    break
        except Exception:
            pass

    if ctx.grey_box_active and ctx.q2_class_root in AUTH_STATE_DEPENDENT:
        ctx.impact_boost += 0.10
        ctx.impact_notes.append(
            f"Grey-box mode (session='{ctx.session_name}' authenticated): "
            f"{ctx.q2_class_root} carries cross-tenant / privilege-escalation impact (+10%)"
        )

    # ── Predictable/sequential-ID escalator (independent of biz context) ──
    if any(s in ctx.evidence_lower for s in _ID_ENUM_SIGNALS):
        ctx.impact_boost += 0.08
        ctx.impact_notes.append(
            "Predictable/sequential ID exposure (+8%): ID range is fuzzable; "
            "full record set enumerable and likely reusable across apps in same ecosystem"
        )

    # ── Vuln-class × business-context amplifiers ──
    for (vtype, ctxkey), reason in _HIGH_IMPACT_COMBOS.items():
        if vtype in ctx.vuln_lower and (ctxkey in biz or ctxkey in env):
            ctx.impact_boost += 0.05
            ctx.impact_notes.append(f"High-impact combo: {reason}")
            break
