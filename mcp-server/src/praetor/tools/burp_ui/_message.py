"""screenshot_message — one request/response auto-scrolled to + highlighting a keyword."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._shared import _pick_attach, _run_auto_redact, _save_shot, _scan_text


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def screenshot_message(proxy_history_index: int, domain: str = "",
                                 which: str = "both", search: str = "",
                                 payload: str = "", keywords: list[str] | None = None,
                                 viewport_height: int = 760, viewport_width: int = 1000,
                                 scale: float = 2.0, note: str = "", finding_id: str = "",
                                 step: str = "", auto_redact: bool = False,
                                 attach: str = "auto") -> dict:
        """Screenshot ONE request/response auto-scrolled to + highlighting a keyword.

        For evidence when the message is too long to fit a Burp viewport: renders the
        proxy-history entry's request AND response in private read-only Burp editors
        (Raw view, stacked — real proxy-history evidence), applies Burp's NATIVE
        search (highlights every match, scrolls the first into view), and captures
        that — so the shot lands ON the interesting line, not the top of a 3000-line
        body. The operator's live Burp UI is never navigated.

        `search` is applied verbatim if given. Otherwise the keyword is auto-picked
        from the message: the finding's `payload` if it reflects, else any `keywords`
        present, else the highest-value evidence shape (exposed key/secret, passwd,
        JWT, SQL/stack-trace error, exposed path). Empty match => shot from the top.

        Args:
            proxy_history_index: get_proxy_history index of the entry to render.
            domain: target the shot belongs to (its screenshots dir). Empty -> _burp.
            which: 'both' (default, request+response stacked), 'response', or 'request'.
            search: explicit search expression (skips auto-pick).
            payload: the finding's payload — auto-search highlights it when reflected.
            keywords: operator keywords to try (in order) before the evidence shapes.
            viewport_height: editor viewport px (how much of the message shows; 760 default).
            viewport_width: editor viewport px width (1000 default).
            scale: render scale (2× default, capped ~2K long side).
            note/finding_id/step: caption + attach (same as burp_screenshot).
            auto_redact: OCR-detect secrets and write a pixel-mosaicked twin.
            attach: which twin to link to finding_id — 'auto'/'naked'/'none'.
        """
        if proxy_history_index < 0:
            return {"error": "proxy_history_index must be >= 0"}
        w = which.strip().lower()
        which_l = "request" if w.startswith("req") else ("response" if w.startswith("res") else "both")
        # Scan the response for the keyword (richest evidence) unless request-only.
        scan_side = "request" if which_l == "request" else "response"
        term, reason = search.strip(), "explicit"
        if not term:
            detail = await client.get(f"/api/proxy/history/{proxy_history_index}")
            if isinstance(detail, dict) and "error" in detail:
                return detail
            from praetor.tools._evidence_keywords import pick_search_term
            term, reason = pick_search_term(
                _scan_text(detail, scan_side), payload, tuple(keywords or ()))
        data = await client.post("/api/ui/message-screenshot", json={
            "proxy_index": proxy_history_index, "which": which_l, "search": term,
            "width": viewport_width, "height": viewport_height, "scale": scale,
        })
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, f"msg-{which_l}", note, finding_id, step)
        if "error" in out:
            return out
        out["which"] = data.get("which", which_l)
        out["search"] = data.get("search", term)
        out["search_reason"] = reason if term else "none_matched"
        out["engine"] = data.get("engine", "")
        if auto_redact:
            r = await _run_auto_redact(out["saved"])
            out["redacted"] = r.get("redacted", "")
            out["redacted_regions"] = r.get("regions", 0)
            if "error" in r:
                out["redact_error"] = r["error"]
        attach_path = _pick_attach(out["saved"], out.get("redacted", ""), attach)
        if finding_id and domain and attach_path:
            from praetor.tools.notes._screenshot_attach import _attach_screenshot
            out["attached"] = await asyncio.to_thread(
                _attach_screenshot, domain, finding_id, attach_path, note, step)
            out["attached_file"] = Path(attach_path).name
        return out
