"""Read-side notes tools: get_findings, export_report."""

import json

from mcp.server.fastmcp import FastMCP

from praetor import client


def register(mcp: FastMCP):

    _SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    @mcp.tool()
    async def get_findings(
        endpoint: str = "",
        severity_min: str = "",
        status: str = "",
        limit: int = 25,
        offset: int = 0,
        summary_only: bool = False,
    ) -> dict:
        """Get saved pentest findings. Paginated and severity-filterable.

        Defaults to the 25 highest-severity findings. On an engagement with
        dozens of findings, returning all of them at full detail floods the
        context and degrades every later decision — filter to what you are
        acting on, then page.

        Returns {total, returned, offset, next_offset, findings, human_summary}.

        Args:
            endpoint: Filter by endpoint URL substring (empty = all)
            severity_min: Only CRITICAL/HIGH/MEDIUM/LOW/INFO and above
            status: Filter by status (confirmed / suspected / stale / ...)
            limit: Max findings returned (1-100). Default 25.
            offset: Skip this many after sorting — page with next_offset.
            summary_only: One line per finding, no descriptions or evidence.
                Cheapest way to see the whole board.
        """
        params = {}
        if endpoint:
            params["endpoint"] = endpoint

        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return {"error": data["error"]}

        findings = data.get("findings", []) or []
        if status:
            want = status.strip().lower()
            findings = [f for f in findings if (f.get("status") or "").lower() == want]
        if severity_min:
            floor = _SEV_RANK.get(severity_min.strip().upper(), 0)
            findings = [
                f for f in findings
                if _SEV_RANK.get((f.get("severity") or "INFO").upper(), 0) >= floor
            ]

        total = len(findings)
        if not findings:
            return {
                "total": 0, "returned": 0, "offset": 0, "next_offset": None,
                "findings": [], "human_summary": "No findings match.",
            }

        # Highest severity first — the finding you should act on leads the page.
        findings.sort(
            key=lambda f: -_SEV_RANK.get((f.get("severity") or "INFO").upper(), 0)
        )

        limit = max(1, min(100, int(limit or 25)))
        offset = max(0, int(offset or 0))
        page = findings[offset:offset + limit]
        next_offset = offset + limit if offset + limit < total else None

        lines = [f"Findings {offset + 1}-{offset + len(page)} of {total}:"]
        for f in page:
            lines.append(
                f"[{f.get('severity')}] {f.get('id')} {f.get('title')} "
                f"— {f.get('endpoint', '')} ({f.get('status', 'suspected')})"
            )
            if not summary_only and f.get("description"):
                lines.append(f"    {f['description'][:200]}")
        if next_offset is not None:
            lines.append(f"... {total - (offset + len(page))} more — offset={next_offset}")

        # Rule 29. A board with nothing at MEDIUM or above means the target has
        # been fingerprinted, not tested — and a pile of INFO findings is what
        # programs close as Informative. Say so while there is still session
        # left to change approach, not at report time.
        if total >= 3 and not any(
            _SEV_RANK.get((f.get("severity") or "INFO").upper(), 0) >= _SEV_RANK["MEDIUM"]
            for f in findings
        ):
            lines.append("")
            lines.append(
                f"Rule 29: all {total} findings are LOW/INFO. Escalate before filing — "
                "ask what each one ENABLES (propose_chains), or move to authorization "
                "(test_auth_matrix), auth/session, and business-logic surface where "
                "MEDIUM+ lives."
            )

        return {
            "total": total,
            "returned": len(page),
            "offset": offset,
            "next_offset": next_offset,
            "findings": [] if summary_only else page,
            "human_summary": "\n".join(lines),
        }

    @mcp.tool()
    async def export_report(format: str = "markdown") -> str:
        """Export all findings as a pentest report.

        Args:
            format: 'markdown' or 'json'
        """
        data = await client.get("/api/notes/export", params={"format": format})
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return data.get("content", "No findings to export.")
