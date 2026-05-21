"""Q4: deduplication against persisted findings.

Match on (endpoint, vuln_root, parameter) tuple. Dedup applies ONLY when
both new and existing finding have non-empty parameter that matches —
empty parameter on either side means "treat as distinct."

Best-effort: missing intel files don't crash.
"""

import json
import re
from pathlib import Path

from ..advisor._context import AssessContext
from ..advisor._helpers import vuln_root
from . import CheckResult


async def check(ctx: AssessContext) -> CheckResult:
    if "q4_dedup" in ctx.override_set:
        # No issue message in original — override is silent for q4
        return {"passed": True, "reason": "override", "evidence": {}}
    if not ctx.domain or ctx.verdict != "REPORT":
        return {"passed": True, "reason": "skip", "evidence": {}}

    try:
        sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', ctx.domain)
        findings_path = Path.cwd() / ".burp-intel" / sanitized / "findings.json"
        if not findings_path.exists():
            return {"passed": True, "reason": "no-findings", "evidence": {}}
        existing = json.loads(findings_path.read_text()).get("findings", [])
        new_root = vuln_root(ctx.vuln_lower)
        for f in existing:
            same_ep = f.get("endpoint", "") == ctx.endpoint
            existing_root = vuln_root(f.get("vuln_type", ""))
            same_type = new_root and existing_root and new_root == existing_root
            existing_param = f.get("parameter", "") or ""
            if not ctx.parameter or not existing_param:
                same_param = False
            else:
                same_param = existing_param == ctx.parameter
            if same_ep and same_type and same_param:
                ctx.issues.append(
                    f"Q4 DUPLICATE: already saved as {f.get('id', '?')} — "
                    f"update instead of re-save"
                )
                ctx.verdict = "DO NOT REPORT"
                return {
                    "passed": False,
                    "reason": "duplicate",
                    "evidence": {"existing_id": f.get("id")},
                }
    except (OSError, json.JSONDecodeError, ImportError):
        pass

    return {"passed": True, "reason": "unique", "evidence": {}}
