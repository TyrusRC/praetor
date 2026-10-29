"""Probe Supabase / Firebase / Appwrite backends for missing access controls.

Automates the manual workflow: extract_js_secrets → find backend URL + anon
key → probe common table names → report exposed columns and PII.

Rule 7 compliant: reads column names and row counts only, never actual values.
"""

from __future__ import annotations

import json
import re
from typing import Any

from praetor import client
from praetor.tools.testing._verdict import make_verdict

# Tables common in vibe-coded apps (Lovable, Bolt, v0, Replit).
_COMMON_TABLES = [
    "users", "profiles", "patients", "appointments", "customers",
    "orders", "products", "accounts", "employees", "leads",
    "contacts", "settings", "messages", "payments", "invoices",
    "bookings", "reviews", "comments", "sessions", "documents",
    "teams", "roles", "subscriptions", "transactions", "services",
]

_PII_KEYWORDS = frozenset([
    "name", "email", "phone", "address", "ssn", "salary",
    "password", "token", "secret", "dob", "birth", "whatsapp",
    "credit_card", "card_number", "social_security",
])


def _is_pii(col: str) -> bool:
    cl = col.lower()
    return any(k in cl for k in _PII_KEYWORDS)


def _extract_supabase_from_secrets(secrets: list[dict]) -> tuple[str, str]:
    """Pull the Supabase URL and anon key from extract_js_secrets output."""
    url = ""
    key = ""
    for s in secrets:
        stype = (s.get("type") or "").lower()
        ctx = s.get("context", "") or s.get("match", "")
        if "supabase" in stype or "supabase" in ctx.lower():
            # Extract URL
            m = re.search(r'https://[a-z]+\.supabase\.co', ctx)
            if m:
                url = m.group(0)
            # Extract key (JWT)
            m = re.search(
                r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                ctx,
            )
            if m:
                key = m.group(0)
    return url, key


async def probe_baas_rls_impl(
    supabase_url: str = "",
    anon_key: str = "",
    proxy_history_index: int = -1,
    tables: list[str] | None = None,
    backend: str = "supabase",
) -> dict[str, Any]:
    """Probe a BaaS backend for missing Row Level Security.

    Accepts either explicit credentials or a proxy_history_index pointing at
    the JS bundle — in the latter case, calls the Java extract_js_secrets
    endpoint to pull the Supabase URL and anon key automatically.
    """
    # Step 1: resolve credentials
    if not supabase_url or not anon_key:
        if proxy_history_index < 0:
            return {"error": "Provide supabase_url + anon_key, or proxy_history_index of the JS bundle"}
        data = await client.post("/api/analysis/js-secrets", json={"index": proxy_history_index})
        if "error" in data:
            return {"error": f"extract_js_secrets failed: {data['error']}"}
        supabase_url, anon_key = _extract_supabase_from_secrets(data.get("secrets", []))
        if not supabase_url or not anon_key:
            return {"error": "No Supabase URL or anon key found in the JS bundle secrets"}

    probe_tables = tables or _COMMON_TABLES
    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}

    exposed: list[dict] = []
    denied: list[str] = []
    errors: list[str] = []

    for table in probe_tables:
        url = f"{supabase_url.rstrip('/')}/rest/v1/{table}?select=*&limit=1"
        try:
            resp = await client.post("/api/http/curl", json={
                "url": url,
                "method": "GET",
                "headers": headers,
                "follow_redirects": False,
            })
        except Exception as e:
            errors.append(f"{table}: {e}")
            continue

        status = resp.get("status_code", 0)
        if status == 200:
            body = resp.get("response_body", "")
            try:
                rows = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                rows = []

            columns: list[str] = []
            has_data = False
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                columns = list(rows[0].keys())
                has_data = True
            elif isinstance(rows, list) and not rows:
                # Table exists, accessible, but empty — get columns from schema
                pass

            pii_cols = [c for c in columns if _is_pii(c)]
            exposed.append({
                "table": table,
                "columns": columns,
                "column_count": len(columns),
                "pii_columns": pii_cols,
                "has_data": has_data,
            })
        elif status in (401, 403):
            denied.append(table)
        # 404 = table doesn't exist, skip silently

    # Build verdict
    pii_exposed = any(t["pii_columns"] for t in exposed)
    data_exposed = any(t["has_data"] for t in exposed)

    if exposed and pii_exposed and data_exposed:
        verdict = "CONFIRMED"
        confidence = 0.95
        severity = "critical"
        summary = (
            f"Supabase RLS disabled: {len(exposed)} tables exposed, "
            f"PII in {sum(1 for t in exposed if t['pii_columns'])} tables"
        )
    elif exposed and data_exposed:
        verdict = "CONFIRMED"
        confidence = 0.85
        severity = "high"
        summary = f"Supabase RLS disabled: {len(exposed)} tables with data exposed (no PII columns detected)"
    elif exposed:
        verdict = "SUSPECTED"
        confidence = 0.6
        severity = "medium"
        summary = f"Supabase RLS disabled: {len(exposed)} empty tables accessible"
    else:
        verdict = "FAILED"
        confidence = 0.1
        severity = None
        summary = f"RLS appears enabled: {len(denied)} tables denied, 0 exposed"

    lines = [
        f"# BaaS RLS Probe — {supabase_url}",
        f"Backend: {backend}",
        f"Tables probed: {len(probe_tables)}",
        f"Exposed: {len(exposed)} | Denied: {len(denied)} | Errors: {len(errors)}",
        "",
    ]
    if exposed:
        lines.append("## Exposed Tables")
        for t in exposed:
            pii_tag = f" ** PII: {t['pii_columns']} **" if t["pii_columns"] else ""
            data_tag = " (has data)" if t["has_data"] else " (empty)"
            lines.append(f"  {t['table']}: {t['column_count']} columns{data_tag}{pii_tag}")
            if t["columns"]:
                lines.append(f"    Columns: {t['columns']}")
        lines.append("")
    if errors:
        lines.append(f"Errors: {errors}")

    result = make_verdict(
        verdict, confidence,
        "\n".join(lines),
        vuln_type="idor",
        summary=summary,
    )
    result["supabase_url"] = supabase_url
    result["tables_exposed"] = exposed
    result["tables_denied_count"] = len(denied)
    return result
