"""test_race_condition — fire N identical requests in a synchronised burst.

Transport model:
  - h1_concurrent (default): Java CountDownLatch barrier + thread-pool concurrent
    HTTP/1.1 sends through Burp. Catches most race conditions where the backend
    is the bottleneck. Implementation: AttackHandler.handleRaceCondition.
  - h2_last_byte (placeholder): true HTTP/2 multiplex + final-byte hold. NOT
    YET IMPLEMENTED — falls back to h1_concurrent with a warning. Requires
    direct h2-library frame control; tracked for future iteration.

Race-window widening:
  - pre_load: fire N warm-up requests via the session 100ms before the
    synchronised burst. Backend caches / connection pools / DB warm up,
    making the actual race window wider when the latch releases.

Cross-channel mode:
  - cross_channel_endpoints: optional list of (transport, request) tuples to
    fire alongside the primary REST race — e.g. same logical operation over
    GraphQL or WebSocket. Confirms cross-channel race exploitability.
"""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import fmt_size


async def _pre_load_burst(session: str, request: dict, count: int) -> None:
    """Fire `count` warm-up requests sequentially as fast as possible to load the backend."""
    method = request.get("method", "POST")
    path = request.get("path", "/")
    headers = request.get("headers", {"Content-Type": "application/json"})
    body = request.get("body", "")
    if isinstance(body, dict):
        body = json.dumps(body)
    tasks = []
    for _ in range(count):
        tasks.append(client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": headers, "body": body,
        }))
    await asyncio.gather(*tasks, return_exceptions=True)


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_race_condition(  # cost: medium (N concurrent requests, single endpoint)
        session: str,
        request: dict,
        concurrent: int = 10,
        expect_once: bool = True,
        transport_mode: str = "h1_concurrent",
        pre_load: int = 0,
        cross_channel_endpoints: list[dict] | None = None,
    ) -> str:
        """Fire N identical requests simultaneously to detect race conditions.

        Args:
            session: Session name
            request: Request spec with method, path, and body
            concurrent: Number of simultaneous requests (max 50)
            expect_once: Flag if action succeeded more than once
            transport_mode: 'h1_concurrent' (default) | 'h2_last_byte' (placeholder, falls back with warning)
            pre_load: Number of warm-up requests to fire before the burst (widens the race window by loading the backend)
            cross_channel_endpoints: Optional list of {transport, request} for parallel firing across REST/GraphQL/WS to confirm cross-channel races
        """
        notes: list[str] = []
        if transport_mode == "h2_last_byte":
            notes.append("transport_mode=h2_last_byte not yet implemented — falling back to h1_concurrent. Track Java AttackHandler for h2 frame control.")
            transport_mode = "h1_concurrent"
        elif transport_mode != "h1_concurrent":
            return f"Error: invalid transport_mode '{transport_mode}' — use h1_concurrent or h2_last_byte"

        if pre_load > 0:
            await _pre_load_burst(session, request, min(pre_load, 50))
            notes.append(f"pre_load: {min(pre_load, 50)} warm-up requests fired")

        # Cross-channel parallel burst (alongside main race)
        cross_tasks: list = []
        if cross_channel_endpoints:
            for ep in cross_channel_endpoints:
                transport = ep.get("transport", "rest")
                req = ep.get("request", {})
                if transport == "rest":
                    cross_tasks.append(client.post("/api/session/request", json={
                        "session": session,
                        "method": req.get("method", "POST"),
                        "path": req.get("path", "/"),
                        "headers": req.get("headers", {"Content-Type": "application/json"}),
                        "body": json.dumps(req.get("body", {})) if isinstance(req.get("body"), dict) else req.get("body", ""),
                    }))
                elif transport == "graphql":
                    cross_tasks.append(client.post("/api/session/request", json={
                        "session": session, "method": "POST", "path": req.get("path", "/graphql"),
                        "headers": {"Content-Type": "application/json"},
                        "body": json.dumps({"query": req.get("query", "{ __typename }")}),
                    }))
                elif transport == "websocket":
                    # Best-effort: ws send via the websocket handler
                    cross_tasks.append(client.post("/api/websocket-send/send", json={
                        "connection_id": req.get("connection_id", ""),
                        "message": req.get("message", ""),
                    }))
                else:
                    notes.append(f"cross-channel: unknown transport '{transport}' — skipped")

        # Fire main race + cross-channel concurrently
        main_task = client.post("/api/attack/race", json={
            "session": session,
            "request": request,
            "concurrent": concurrent,
            "expect_once": expect_once,
        })
        if cross_tasks:
            results = await asyncio.gather(main_task, *cross_tasks, return_exceptions=True)
            data = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
            cross_results = results[1:]
        else:
            data = await main_task
            cross_results = []

        if "error" in data:
            return f"Error: {data['error']}"

        lines = []
        for n in notes:
            lines.append(f"# {n}")
        if notes:
            lines.append("")

        lines.append(f"[main race] {data['concurrent']} requests sent in {data['total_time_ms']}ms window")
        dist = data.get("status_distribution", {})
        dist_str = ", ".join(f"{status}x{count}" for status, count in dist.items())
        lines.append(f"Status distribution: {dist_str}")
        lines.append(f"Success count: {data['success_count']}")
        if not data.get("race_synchronised", True):
            lines.append("Race not synchronised — successCount unreliable.")

        if data.get("vulnerable"):
            lines.append(f"\n*** {data['finding']} ***")

        lines.append("\nResponse breakdown:")
        for r in data.get("results", []):
            preview = r.get("body_preview", "")
            if len(preview) > 100:
                preview = preview[:100] + "..."
            length = r.get('response_length', r.get('length', 0))
            lines.append(f"  #{r['index']}: {r['status']} ({fmt_size(length)}) {r['time_ms']}ms — {preview}")

        if cross_results:
            lines.append("\n[cross-channel]")
            for i, cr in enumerate(cross_results):
                ep = cross_channel_endpoints[i] if i < len(cross_channel_endpoints) else {}
                transport = ep.get("transport", "?")
                if isinstance(cr, Exception):
                    lines.append(f"  {transport}: exception — {cr}")
                    continue
                if "error" in cr:
                    lines.append(f"  {transport}: error — {cr['error']}")
                    continue
                s = cr.get("status", 0)
                ln = len(cr.get("response_body", "") or cr.get("body", "") or "")
                lines.append(f"  {transport}: status={s} len={ln}")
            success_x_channel = sum(
                1 for cr in cross_results
                if not isinstance(cr, Exception) and "error" not in cr
                and 200 <= cr.get("status", 0) < 300
            )
            if data.get("vulnerable") and success_x_channel >= 1:
                lines.append("\n*** CROSS-CHANNEL RACE CONFIRMED *** — race exploitable from ≥2 transports simultaneously.")

        return "\n".join(lines)
