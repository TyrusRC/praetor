"""test_cache_poisoning — unkeyed-header injection, cache deception, parameter cloaking."""

import hashlib
import time

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import scope_or_error


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_cache_poisoning(session: str, path: str = "/") -> str:
        """Test for web cache poisoning and cache deception via unkeyed headers and parameter cloaking.

        Args:
            session: Session name for auth state
            path: Target endpoint path (default /)
        """
        lines = [f"Cache Poisoning Tests: {path}\n"]
        findings = []

        host_info = await client.get_session_last_host(session)
        if "error" in host_info:
            return f"Error: {host_info['error']}"
        scope_err = await scope_or_error(host_info["host"], host_info.get("https", True), host_info.get("port", 443))
        if scope_err:
            return scope_err

        cb = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        # Test 1: Unkeyed header injection
        lines.append("--- Test 1: Unkeyed Header Injection ---")
        unkeyed_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "http"),
            ("X-Original-URL", "/evil"),
            ("X-Rewrite-URL", "/evil"),
            ("X-Forwarded-Prefix", "/evil"),
        ]

        for header_name, header_value in unkeyed_headers:
            cache_path = f"{path}?cb={cb}-{header_name[:4]}"
            resp1 = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": cache_path,
                "headers": {header_name: header_value},
            })
            if "error" in resp1:
                lines.append(f"  {header_name}: Error — {resp1['error']}")
                continue

            body1 = resp1.get("response_body", "")
            reflected = header_value.lower() in body1.lower()

            if reflected:
                resp2 = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": cache_path,
                })
                body2 = resp2.get("response_body", "") if "error" not in resp2 else ""
                cached = header_value.lower() in body2.lower()

                if cached:
                    findings.append(f"Cache poisoned via {header_name}")
                    lines.append(f"  [!!] {header_name}: CACHE POISONED — evil value persists without header")
                else:
                    lines.append(f"  [!] {header_name}: Reflected but NOT cached")
            else:
                lines.append(f"  {header_name}: Not reflected")

        # Test 2: Cache deception
        lines.append("\n--- Test 2: Cache Deception ---")
        deception_paths = [
            f"{path}/nonexist.css",
            f"{path}/nonexist.js",
            f"{path}/nonexist.png",
            f"{path}%2f..%2fnonexist.css",
        ]

        for test_path in deception_paths:
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": test_path,
            })
            if "error" in resp:
                lines.append(f"  {test_path}: Error")
                continue

            status = resp.get("status", 0)
            body = resp.get("response_body", "")

            cache_control = ""
            is_cached = False
            for h in resp.get("response_headers", []):
                hname = h.get("name", "").lower() if isinstance(h, dict) else ""
                hval = h.get("value", "") if isinstance(h, dict) else ""
                if hname == "cache-control":
                    cache_control = hval
                if hname in ("x-cache", "cf-cache-status", "x-varnish"):
                    if "hit" in hval.lower():
                        is_cached = True

            has_auth_content = status == 200 and len(body) > 500

            flags = []
            if is_cached:
                flags.append("CACHED")
            if has_auth_content:
                flags.append("AUTH_CONTENT")
            if cache_control and "no-" not in cache_control.lower():
                flags.append(f"CC:{cache_control[:30]}")

            if is_cached and has_auth_content:
                findings.append(f"Cache deception: {test_path}")
                lines.append(f"  [!!] {test_path}: Cached authenticated content!")
            elif flags:
                lines.append(f"  [!] {test_path}: {' '.join(flags)} (status {status})")
            else:
                lines.append(f"  {test_path}: status={status}, len={len(body)}")

        # Test 3: Parameter cloaking
        lines.append("\n--- Test 3: Parameter Cloaking ---")
        cloak_paths = [
            f"{path}?cb={cb}&utm_content=evil<script>",
            f"{path}?cb={cb};utm_content=evil<script>",
        ]

        for i, cloak_path in enumerate(cloak_paths):
            separator = "&" if i == 0 else ";"
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": cloak_path,
            })
            if "error" in resp:
                lines.append(f"  Separator '{separator}': Error")
                continue

            body = resp.get("response_body", "")
            if "evil<script>" in body or "evil%3Cscript%3E" in body.lower():
                lines.append(f"  [!] Separator '{separator}': Param value reflected")
                resp2 = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": f"{path}?cb={cb}",
                })
                if "error" not in resp2 and "evil" in resp2.get("response_body", ""):
                    findings.append(f"Parameter cloaking with '{separator}'")
                    lines.append(f"  [!!] Poisoned value persists — cache is keyed differently!")
            else:
                lines.append(f"  Separator '{separator}': Not reflected")

        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Findings ({len(findings)}):")
            for f in findings:
                lines.append(f"  [!] {f}")
            lines.append("Risk: Web cache poisoning can serve malicious content to all users.")
        else:
            lines.append("No cache poisoning vulnerabilities detected.")

        return "\n".join(lines)
