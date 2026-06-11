"""probe_kerberos_spnego_auth — SPNEGO / NTLMv2 detection (W29-j).

Burp Suite Pro 2026.1.3 added native SPNEGO + NTLMv2 support — Praetor's
session layer is bearer/cookie only. Full active negotiation requires GSSAPI
(libkrb5), out of scope this wave.

This MVP detects whether a target REQUIRES enterprise auth so the operator
knows when bearer/cookie sessions won't work. Two signals:
  1. WWW-Authenticate response header — `Negotiate` (SPNEGO), `Kerberos`,
     `NTLM`, `NTLMv2`, `Basic`
  2. 401 with no auth header set → enterprise gateway likely

Returns VerdictResult that catalogs which mechanisms are advertised. The
operator should then route session creation via:
  - Linux: `kinit + curl --negotiate -u :` (out-of-band)
  - Windows: rely on machine credentials with `curl --ntlm`
  - Or proxy through a tool like ntlmaps / cntlm
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


_NEGOTIATE_SCHEMES = ("negotiate", "kerberos", "ntlm", "ntlmv2",
                      "basic", "digest", "bearer")


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_kerberos_spnego_auth(  # cost: low (1-2 requests)
        target_url: str,
        timeout: int = 20,
    ) -> dict:
        """Detect SPNEGO / Kerberos / NTLMv2 / Basic / Digest gateway auth.

        Sends a bare GET to target_url (no Authorization header) and parses
        the WWW-Authenticate response header. Vulnerable to nothing — purely
        a discovery probe to inform the operator about session strategy.

        VerdictResult:
          - CONFIRMED — server returns 401 + WWW-Authenticate with a known
            mechanism (Negotiate / NTLM / Basic / Digest / Bearer)
          - SUSPECTED — server returns 401 with no WWW-Authenticate
            (custom gateway behaviour)
          - FAILED — server returns 200 / 3xx (no enterprise auth gateway)

        Args:
            target_url: URL to probe
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(target_url)
        if not scope.get("in_scope"):
            return error_verdict("enterprise_auth_gateway", "out_of_scope",
                                 f"{target_url} not in scope")

        resp = await client.post("/api/http/curl", json={
            "method": "GET",
            "url": target_url,
            "follow_redirects": False,
            "timeout": timeout,
            "bare_headers": True,
        })
        if resp.get("error"):
            return error_verdict("enterprise_auth_gateway", "fetch_failed",
                                 resp.get("error", ""))
        logger_indices = []
        if "logger_index" in resp:
            logger_indices.append(resp["logger_index"])

        status = resp.get("status_code", 0)
        hdrs = {k.lower(): str(v) for k, v in
                (resp.get("response_headers") or {}).items()}
        wwwauth = hdrs.get("www-authenticate", "")
        proxyauth = hdrs.get("proxy-authenticate", "")

        # Multiple WWW-Authenticate headers — server may stack mechanisms
        mechanisms: list[str] = []
        for blob in (wwwauth, proxyauth):
            for entry in blob.split(","):
                entry = entry.strip().split()[0].lower() if entry.strip() else ""
                if entry in _NEGOTIATE_SCHEMES:
                    mechanisms.append(entry)

        if status == 401 and mechanisms:
            negotiate_present = "negotiate" in mechanisms or "kerberos" in mechanisms
            ntlm_present = "ntlm" in mechanisms or "ntlmv2" in mechanisms
            requires_enterprise = negotiate_present or ntlm_present

            return make_verdict(
                vuln_type="enterprise_auth_gateway",
                verdict="CONFIRMED",
                confidence=0.95,
                evidence_summary=f"401 with WWW-Authenticate: {', '.join(set(mechanisms))}",
                logger_indices=logger_indices,
                details={
                    "target_url": target_url,
                    "status": status,
                    "mechanisms": list(set(mechanisms)),
                    "negotiate_supported": negotiate_present,
                    "ntlm_supported": ntlm_present,
                    "requires_enterprise_auth": requires_enterprise,
                    "operator_action": (
                        "Use `kinit + curl --negotiate -u :` (linux) or "
                        "`curl --ntlm` with machine credentials. "
                        "session_request layer does not natively support these "
                        "mechanisms (W29-j detection-only)."
                        if requires_enterprise else
                        "Standard cookie/bearer auth — create_session as usual."
                    ),
                },
                human_summary=f"Enterprise auth: {', '.join(set(mechanisms))}",
            )
        if status == 401:
            return make_verdict(
                vuln_type="enterprise_auth_gateway",
                verdict="SUSPECTED",
                confidence=0.6,
                evidence_summary="401 with no WWW-Authenticate header — custom gateway",
                logger_indices=logger_indices,
                details={"target_url": target_url, "status": 401,
                         "response_headers": hdrs},
                human_summary="401 without WWW-Authenticate — custom auth gateway",
            )
        return make_verdict(
            vuln_type="enterprise_auth_gateway",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary=f"Status {status} — no enterprise auth gateway",
            logger_indices=logger_indices,
            details={"target_url": target_url, "status": status},
            human_summary=f"No enterprise auth gateway (status {status})",
        )
