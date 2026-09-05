"""Proxy annotations: color+comment on captured requests (Rule 18)."""

from mcp.server.fastmcp import FastMCP

import json

from praetor import client
from ._helpers import _lookup_finding_id, _record_annotation_on_finding


def register(mcp: FastMCP):

    @mcp.tool()
    async def annotate_request(
        index: int,
        color: str = "",
        comment: str = "",
        endpoint: str = "",
        finding_id: str = "",
        confirm: bool = False,
    ) -> str:
        """Mark a proxy history item with a color and/or comment in Burp's UI. Read-back verified.

        A RED or ORANGE tag is a claim ("this entry proves finding X"). Those
        colors require either a `finding_id` that resolves in .burp-intel, or
        `confirm=True`. Everything else annotates freely.

        Args:
            index: Proxy history index (Proxy -> HTTP history, NOT a Logger index)
            color: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY
            comment: Note text. Rule 18 format: '<f-id> | <vuln> | <evidence>'
            endpoint: Endpoint the annotation is about. Server refuses to tag an
                unrelated request when supplied — always pass it for claim colors.
            finding_id: Saved finding this tag refers to (e.g. 'f003'). Verified to exist.
            confirm: Operator override when a claim color has no saved finding yet.
        """
        color_upper = (color or "").upper()
        claim_color = color_upper in ("RED", "ORANGE")

        if finding_id:
            known, where = _lookup_finding_id(finding_id)
            if not known:
                return (
                    f"Refused: finding_id={finding_id!r} does not exist in .burp-intel. "
                    f"Annotating a request with a finding ID that was never saved is how "
                    f"writeups end up citing comments Burp never had.\n"
                    f"  Fix: save_finding(...) first, then annotate with the returned ID — "
                    f"or drop finding_id and annotate with a plain observation."
                )
            claim_color = False  # a resolvable ID is the evidence the gate wanted
            comment = comment or f"{finding_id} | see {where}"

        if claim_color and not confirm:
            return (
                f"QUESTION GATE — {color_upper} marks a confirmed/strong-suspicion claim on "
                f"proxy entry #{index}, but no finding_id was given.\n"
                f"  Comment: {comment or '(none)'}\n"
                f"  Answer one:\n"
                f"    a) pass finding_id='fNNN' if the finding is already saved;\n"
                f"    b) pass confirm=True if you have verified this entry yourself;\n"
                f"    c) use YELLOW (anomaly) or CYAN (chain candidate) — no claim implied."
            )

        payload: dict = {"index": index, "color": color, "comment": comment}
        if endpoint:
            payload["endpoint"] = endpoint
        data = await client.post("/api/annotations/set", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        # Report what Burp actually stored, not what we asked for. A later
        # get_annotations(index) returns exactly this.
        stored_color = data.get("color", "NONE")
        stored_notes = data.get("notes", "")
        url = data.get("url", "")
        method = data.get("method", "")

        # Record the read-back on the finding. A writeup may then cite only tags
        # that Burp confirmed storing — the "the md says I commented X but the
        # history has no such comment" failure comes from citing the requested
        # text instead of the stored text.
        if finding_id:
            _record_annotation_on_finding(
                finding_id,
                {"index": index, "color": stored_color, "comment": stored_notes,
                 "url": url, "method": method},
            )

        lines = [f"Annotated #{index} — verified in Burp:"]
        lines.append(f"  color:   {stored_color}")
        lines.append(f"  comment: {stored_notes or '(none)'}")
        if url:
            lines.append(f"  entry:   {method} {url}")
        if comment and stored_notes != comment:
            lines.append(
                "  WARNING: Burp stored a different comment than requested. "
                "Cite the stored text above, not the requested text."
            )
        return "\n".join(lines)

    @mcp.tool()
    async def annotate_bulk(items: list[dict], confirm: bool = False) -> str:
        """Annotate multiple proxy history items at once. Claim colors are gated.

        RED and ORANGE assert "this entry proves finding X" exactly as they do
        on annotate_request, so they carry the same gate here — a bulk call is
        not a way around it. Batches of unverified claim colors are what leave a
        history full of RED entries no finding stands behind.

        Args:
            items: List of dicts: {index, color?, comment?, endpoint?, finding_id?}.
                `endpoint` makes the server refuse to tag an unrelated request.
            confirm: Operator override for claim colors with no saved finding.
        """
        blocked: list[str] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            color_upper = str(it.get("color") or "").upper()
            if color_upper not in ("RED", "ORANGE"):
                continue
            fid = str(it.get("finding_id") or "").strip()
            if fid:
                known, _where = _lookup_finding_id(fid)
                if not known:
                    blocked.append(
                        f"#{it.get('index', '?')} {color_upper}: finding_id "
                        f"{fid!r} does not exist in .burp-intel"
                    )
                continue
            if not confirm:
                blocked.append(
                    f"#{it.get('index', '?')} {color_upper}: no finding_id"
                )

        if blocked:
            return (
                "QUESTION GATE — nothing annotated. "
                f"{len(blocked)} of {len(items)} entries make a claim "
                "(RED/ORANGE) with nothing backing it:\n"
                + "\n".join(f"    - {b}" for b in blocked[:10])
                + ("\n    ..." if len(blocked) > 10 else "")
                + "\n  Answer one:\n"
                "    a) add finding_id='fNNN' per entry once the finding is saved;\n"
                "    b) pass confirm=True if you verified these entries yourself;\n"
                "    c) downgrade to YELLOW (anomaly) or CYAN (chain candidate)."
            )

        data = await client.post("/api/annotations/bulk", json={"items": items})
        if "error" in data:
            return f"Error: {data['error']}"
        applied = data.get("applied", 0)
        errors = data.get("errors", []) or []
        out = [f"Annotated {applied} of {len(items)} items"]
        if errors:
            out.append(f"  Rejected {len(errors)}:")
            out.extend(f"    - {e}" for e in errors[:10])
            out.append("  Rejected entries carry NO annotation — do not cite them as tagged.")
        return "\n".join(out)

    @mcp.tool()
    async def get_annotations(index: int) -> str:
        """Get the current annotation (color and comment) for a proxy history item.

        Args:
            index: Proxy history index
        """
        data = await client.get(f"/api/annotations/{index}")
        if "error" in data:
            return f"Error: {data['error']}"
        color = data.get("color", "NONE")
        comment = data.get("notes", "")
        if color == "NONE" and not comment:
            return f"#{index}: no annotations"
        return f"#{index}: color={color}, comment={comment}"

    # ── Statistics & Live Traffic ────────────────────────────────
