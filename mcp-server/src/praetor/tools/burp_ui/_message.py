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
                                 which: str = "both", layout: str = "side",
                                 search: str = "", payload: str = "",
                                 keywords: list[str] | None = None,
                                 highlight: str = "box", tool: str = "proxy",
                                 include_history_row: bool = True,
                                 viewport_height: int = 640, viewport_width: int = 0,
                                 scale: float = 2.5, note: str = "", finding_id: str = "",
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
            which: 'both' (default, request+response), 'response', or 'request'.
            layout: 'side' (default, Repeater-style Request | Response) or 'stacked'.
            tool: chrome to draw around the panes — 'proxy' (default, HTTP-history
                row), 'logger' (Logger row), or 'repeater' (numbered request tabs,
                no table). Use the tool the evidence traffic actually came from.
            search: explicit search expression (skips auto-pick).
            payload: the finding's payload — auto-search highlights it when reflected.
            keywords: operator keywords to try (in order) before the evidence shapes.
            highlight: how to mark the match — 'box' (red call-out only, default),
                'yellow' (Burp's native yellow only), 'both' (red box + yellow), or
                'none'. Ask the operator which they want, like naked-vs-redacted.
            include_history_row: draw the Proxy > HTTP history tab bar + the entry's
                real row (#/Host/Method/URL/Status/Length/MIME/Title) on top. Default True.
            viewport_height: editor viewport px (how much of the message shows; 760).
            viewport_width: editor viewport px width (0 = auto: 1600 side / 1000 else).
            scale: render scale (2× default).
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
        # Fetch the entry detail if we need it — to auto-pick the keyword and/or to
        # draw the HTTP-history context row on top.
        detail = None
        if not search.strip() or include_history_row:
            detail = await client.get(f"/api/proxy/history/{proxy_history_index}")
            if isinstance(detail, dict) and "error" in detail:
                return detail
        term, reason = search.strip(), "explicit"
        if not term:
            from praetor.tools._evidence_keywords import pick_search_term
            term, reason = pick_search_term(
                _scan_text(detail, scan_side), payload, tuple(keywords or ()))
        layout_l = "stacked" if layout.strip().lower().startswith("stack") else "side"
        payload_json = {
            "proxy_index": proxy_history_index, "which": which_l, "layout": layout_l,
            "search": term, "height": viewport_height, "scale": scale,
        }
        if viewport_width > 0:   # 0 = let the handler auto-size (1600 side / 1000 else)
            payload_json["width"] = viewport_width
        data = await client.post("/api/ui/message-screenshot", json=payload_json)
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, f"msg-{which_l}", note, finding_id, step)
        if "error" in out:
            return out
        out["which"] = data.get("which", which_l)
        out["layout"] = data.get("layout", layout_l)
        out["search"] = data.get("search", term)
        out["search_reason"] = reason if term else "none_matched"
        out["engine"] = data.get("engine", "")
        # Mark the match per the operator's choice:
        #   box    red call-out only  (draw box, clear the scroll-yellow)
        #   both   red box + yellow   (draw box, keep yellow)
        #   yellow Burp's native yellow only (leave as-is)
        #   none   no marker          (clear the scroll-yellow, no box)
        hl = (highlight or "box").strip().lower()
        if hl not in ("box", "both", "yellow", "none"):
            hl = "box"
        out["highlight"] = hl
        if term and hl != "yellow":
            from praetor.tools._highlight_box import annotate_highlights
            out["highlight_boxes"] = await asyncio.to_thread(
                annotate_highlights, out["saved"], 7, 4,
                hl in ("box", "both"), hl in ("box", "none"))
        # Draw the Proxy > HTTP history context row (real metadata) on top, so the
        # shot reads as proxy-history evidence. Done AFTER boxing (box coords are
        # relative to the panes, before the header shifts them down).
        if include_history_row and isinstance(detail, dict):
            from praetor.tools._history_header import prepend_history_header
            # Draw the chrome header at ~0.77x the pane scale so the HTTP message
            # text stays the largest, most prominent element (evidence-first).
            out["history_header_px"] = await asyncio.to_thread(
                prepend_history_header, out["saved"], detail, proxy_history_index,
                max(1.0, scale * 0.77), data.get("burp_title", ""),
                data.get("burp_icon_b64", ""), tool)
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
