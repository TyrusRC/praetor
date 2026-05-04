"""Burp Comparer integration + enhanced response diff."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_to_comparer(index1: int, index2: int) -> str:
        """Send two proxy history items to Burp's Comparer tab.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
        """
        data = await client.post("/api/search/send-to-comparer", json={
            "index1": index1,
            "index2": index2,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Comparer")

    @mcp.tool()
    async def compare_responses(
        index1: int,
        index2: int,
        mode: str = "full",
    ) -> str:
        """Detailed diff between two proxy history items with header and body analysis.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
            mode: Comparison mode: 'full', 'headers', or 'body'
        """
        data = await client.post("/api/search/compare", json={
            "index1": index1,
            "index2": index2,
            "mode": mode,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Enhanced Comparison: #{index1} vs #{index2} (mode: {mode})\n"]

        status = data.get("status_diff", {})
        if status:
            lines.append(f"Status: {status.get('item1', '?')} vs {status.get('item2', '?')}")

        length = data.get("length_diff", {})
        if length:
            lines.append(f"Length: {length.get('item1', '?')} vs {length.get('item2', '?')}")

        # Header diffs
        header_diffs = data.get("header_diffs", [])
        if header_diffs:
            lines.append(f"\n--- Header Differences ({len(header_diffs)}) ---")
            for h in header_diffs:
                lines.append(f"  {h.get('name')}: {h.get('item1', '(absent)')} vs {h.get('item2', '(absent)')}")

        # Body diff
        body = data.get("body_diff", {})
        if body:
            lines.append(f"\n--- Body Diff ---")
            lines.append(f"  Identical: {body.get('identical', False)}")
            if "similarity_pct" in body:
                lines.append(f"  Similarity: {body['similarity_pct']}%")
            lines.append(f"  Added: {body.get('added_lines', 0)} | Removed: {body.get('removed_lines', 0)}")
            for line in body.get("diff_lines", [])[:50]:
                lines.append(f"  {line}")

        # Unique words
        u1 = data.get("unique_to_item1", [])
        u2 = data.get("unique_to_item2", [])
        if u1:
            lines.append(f"\nUnique to #{index1}: {', '.join(u1[:20])}")
        if u2:
            lines.append(f"Unique to #{index2}: {', '.join(u2[:20])}")

        return "\n".join(lines)
