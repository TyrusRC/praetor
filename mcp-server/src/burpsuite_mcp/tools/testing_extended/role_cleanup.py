"""probe_role_state_cleanup — verify privilege revocation across downstream services.

Premise: an account is downgraded (paid -> free, admin -> member, etc.). The
auth/role endpoint reports the new state correctly, but downstream services
have stale caches (Redis TTLs, in-memory role maps, JWT not yet expired,
microservice-level role caches). Strix calls this the role-cleanup-after-
downgrade pattern.

Test: same session token, after downgrade, replay privileged-endpoint calls.
Anything still 2xx means stale-state privilege retention.

Pure black-box — operator supplies two session names (pre-downgrade,
post-downgrade) and a list of privileged endpoints exercised on the
pre-downgrade session.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_role_state_cleanup(
        session_pre: str,
        session_post: str,
        privileged_endpoints: list[dict],
        wait_seconds: int = 0,
    ) -> str:
        """Verify privileged endpoints reject the post-downgrade session.

        Operator workflow:
          1. Create session_pre with full privileges.
          2. Capture the privileged endpoints (URL + method + body) by exercising the app.
          3. Trigger the downgrade (cancel subscription / revoke role).
          4. Create session_post with the same credentials AFTER the downgrade.
          5. Call this tool with both sessions and the captured endpoint list.

        Args:
            session_pre: Session that had privileges at capture time.
            session_post: Session captured AFTER privilege revocation.
            privileged_endpoints: list of {method, path, body?, headers?} that returned 2xx pre-downgrade.
            wait_seconds: Optional sleep before testing post-session (lets caches age past TTL).
        """
        if not privileged_endpoints:
            return "Error: privileged_endpoints is empty"

        lines = [
            f"probe_role_state_cleanup",
            f"Pre session: {session_pre}",
            f"Post session: {session_post}",
            f"Endpoints: {len(privileged_endpoints)}",
            "",
        ]

        # Verify pre-session still has privilege (sanity check)
        lines.append("[verify pre-downgrade access on session_pre]")
        pre_ok = 0
        for ep in privileged_endpoints:
            r = await client.post("/api/session/request", json={
                "session": session_pre,
                "method": ep.get("method", "GET"),
                "path": ep["path"],
                "headers": ep.get("headers", {}),
                "body": ep.get("body", ""),
            })
            if "error" in r:
                lines.append(f"  {ep.get('method','GET')} {ep['path']}: ERROR — {r['error']}")
                continue
            s = r.get("status", 0)
            tag = "OK" if 200 <= s < 300 else f"DENIED({s})"
            lines.append(f"  {ep.get('method','GET')} {ep['path']}: {tag}")
            if 200 <= s < 300:
                pre_ok += 1
        if pre_ok == 0:
            lines.append("\nWARNING: pre-downgrade session does not have access to any listed endpoint. Verify the capture is correct.")
            lines.append("\n--- Summary ---")
            lines.append("No pre-downgrade access — cannot evaluate cleanup. Re-run after re-capturing privileged endpoints.")
            return "\n".join(lines)

        if wait_seconds > 0:
            import asyncio
            lines.append(f"\nWaiting {wait_seconds}s for caches to age...")
            await asyncio.sleep(min(wait_seconds, 600))

        lines.append("\n[test post-downgrade access on session_post]")
        retained: list[dict] = []
        for ep in privileged_endpoints:
            r = await client.post("/api/session/request", json={
                "session": session_post,
                "method": ep.get("method", "GET"),
                "path": ep["path"],
                "headers": ep.get("headers", {}),
                "body": ep.get("body", ""),
            })
            if "error" in r:
                lines.append(f"  {ep.get('method','GET')} {ep['path']}: ERROR — {r['error']}")
                continue
            s = r.get("status", 0)
            body = r.get("response_body", "")
            length = len(body)
            if 200 <= s < 300:
                tag = "*** STALE PRIVILEGE RETAINED ***"
                retained.append({
                    "endpoint": f"{ep.get('method','GET')} {ep['path']}",
                    "status": s,
                    "length": length,
                })
            else:
                tag = f"properly denied ({s})"
            lines.append(f"  {ep.get('method','GET')} {ep['path']}: status={s} len={length} {tag}")

        lines.append("\n--- Summary ---")
        if retained:
            lines.append(f"STALE PRIVILEGES: {len(retained)} / {len(privileged_endpoints)} endpoints still grant access after downgrade")
            for r in retained:
                lines.append(f"  [!] {r['endpoint']} status={r['status']} len={r['length']}")
            lines.append("\nRisk: role/permission revocation incomplete — downstream cache or JWT not invalidated. Verify TTL, cache layer (Redis/memcached), and JWT exp logic.")
        else:
            lines.append("All privileged endpoints properly deny the post-downgrade session.")
        return "\n".join(lines)
