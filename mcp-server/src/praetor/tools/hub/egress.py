"""send_finding_to_siem — ship findings to a SIEM/webhook (JSON or CEF).

Consolidation-hub egress for detection/monitoring pipelines: POST confirmed
findings to an operator-owned SIEM HTTP collector or webhook. The call goes to
the OPERATOR'S OWN endpoint (not a pentest target), so it bypasses Burp.

Config comes from environment variables — never hardcoded:
  SIEM_WEBHOOK_URL    fallback when webhook_url is not passed
  SIEM_WEBHOOK_TOKEN  optional bearer token

`_event` / `_cef_line` are pure; the @mcp.tool does the network I/O.
"""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

from ..notes._helpers import _safe_findings_path, _load_findings_file, _find_by_id

_FMTS = {"json", "cef"}
# Praetor tier -> ArcSight CEF numeric severity (0-10).
_CEF_SEV = {"critical": 10, "high": 8, "medium": 5, "low": 3}


def _event(f: dict) -> dict:
    """Compact, SIEM-friendly event dict from a finding. Pure."""
    return {
        "id": f.get("id", ""),
        "title": f.get("title", ""),
        "severity": str(f.get("severity", "") or "low").lower(),
        "endpoint": f.get("endpoint", ""),
        "parameter": f.get("parameter", ""),
        "vuln_type": f.get("vuln_type", ""),
        "cwe": f.get("cwe", ""),
        "cvss": f.get("cvss4_vector") or f.get("cvss_vector") or "",
        "status": f.get("status", ""),
        "impact": f.get("impact", ""),
    }


def _cef_escape(value: str, *, header: bool) -> str:
    """Escape a CEF field. Header fields escape \\ and |; extension values
    escape \\, = and newlines."""
    out = str(value).replace("\\", "\\\\")
    if header:
        return out.replace("|", "\\|")
    return out.replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def _cef_line(f: dict, domain: str) -> str:
    """One ArcSight CEF:0 line derived from a finding. Pure."""
    sev = str(f.get("severity", "") or "low").lower()
    name = _cef_escape(f.get("title", "finding"), header=True)
    sig = _cef_escape(f.get("vuln_type", "") or f.get("id", "praetor"), header=True)
    header = f"CEF:0|Praetor|Praetor|1.0|{sig}|{name}|{_CEF_SEV.get(sev, 3)}|"
    ext = {
        "dvchost": domain,
        "request": f.get("endpoint", ""),
        "cs1Label": "cvss",
        "cs1": f.get("cvss4_vector") or f.get("cvss_vector") or "",
        "cs2Label": "finding_id",
        "cs2": f.get("id", ""),
        "msg": f.get("impact", "") or f.get("title", ""),
    }
    parts = [f"{k}={_cef_escape(v, header=False)}" for k, v in ext.items() if v]
    return header + " ".join(parts)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def send_finding_to_siem(
        domain: str,
        finding_id: str = "",
        webhook_url: str = "",
        fmt: str = "json",
    ) -> dict:
        """POST findings to a SIEM/webhook collector as JSON or ArcSight CEF.

        webhook_url falls back to env SIEM_WEBHOOK_URL; an optional bearer token
        comes from env SIEM_WEBHOOK_TOKEN. fmt: json (application/json) | cef
        (text/plain, one CEF line per finding). If finding_id is empty, sends
        all status='confirmed' findings; otherwise just that one. Returns
        {sent, status_code, fmt}.
        """
        if fmt not in _FMTS:
            return {"error": f"fmt must be one of {sorted(_FMTS)}"}
        url = webhook_url or os.environ.get("SIEM_WEBHOOK_URL", "")
        if not url:
            return {"error": "no webhook_url and SIEM_WEBHOOK_URL not set"}

        data = _load_findings_file(_safe_findings_path(domain))
        findings = data.get("findings", [])
        if finding_id:
            _, f = _find_by_id(findings, finding_id)
            if f is None:
                return {"error": f"finding '{finding_id}' not found in '{domain}'"}
            selected = [f]
        else:
            selected = [f for f in findings if f.get("status") == "confirmed"]
        if not selected:
            return {"sent": 0, "status_code": None, "fmt": fmt}

        headers = {}
        token = os.environ.get("SIEM_WEBHOOK_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        if fmt == "json":
            headers["Content-Type"] = "application/json"
            payload = {"domain": domain, "count": len(selected),
                       "findings": [_event(f) for f in selected]}
            body = None
            kwargs = {"json": payload}
        else:
            headers["Content-Type"] = "text/plain"
            body = "\n".join(_cef_line(f, domain) for f in selected)
            kwargs = {"content": body}

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(url, headers=headers, **kwargs)
        except httpx.HTTPError as e:
            return {"error": f"{type(e).__name__}: {e}"}
        return {"sent": len(selected), "status_code": r.status_code, "fmt": fmt}
