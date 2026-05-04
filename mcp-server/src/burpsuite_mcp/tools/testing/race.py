"""test_race_condition — fire N identical requests in a synchronised burst."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import fmt_size


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_race_condition(  # cost: medium (N concurrent requests, single endpoint)
        session: str,
        request: dict,
        concurrent: int = 10,
        expect_once: bool = True,
    ) -> str:
        """Fire N identical requests simultaneously to detect race conditions.

        Args:
            session: Session name
            request: Request spec with method, path, and body
            concurrent: Number of simultaneous requests (max 50)
            expect_once: Flag if action succeeded more than once
        """
        payload = {
            "session": session,
            "request": request,
            "concurrent": concurrent,
            "expect_once": expect_once,
        }
        data = await client.post("/api/attack/race", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"{data['concurrent']} requests sent in {data['total_time_ms']}ms window"]

        dist = data.get("status_distribution", {})
        dist_str = ", ".join(f"{status}x{count}" for status, count in dist.items())
        lines.append(f"Status distribution: {dist_str}")
        lines.append(f"Success count: {data['success_count']}")

        if data.get("vulnerable"):
            lines.append(f"\n*** {data['finding']} ***")

        lines.append("\nResponse breakdown:")
        for r in data.get("results", []):
            preview = r.get("body_preview", "")
            if len(preview) > 100:
                preview = preview[:100] + "..."
            length = r.get('response_length', r.get('length', 0))
            lines.append(f"  #{r['index']}: {r['status']} ({fmt_size(length)}) {r['time_ms']}ms — {preview}")

        return "\n".join(lines)
