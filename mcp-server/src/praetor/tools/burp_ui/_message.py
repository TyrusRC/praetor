"""screenshot_message — one request/response auto-scrolled to + highlighting a keyword."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._shared import (
    _descriptive_base,
    _pick_attach,
    _run_auto_redact,
    _save_shot,
    _scan_text,
    _size_preset,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def screenshot_message(proxy_history_index: int = -1, domain: str = "",
                                 send_ref: str = "",
                                 which: str = "both", layout: str = "side",
                                 search: str = "", payload: str = "",
                                 keywords: list[str] | None = None,
                                 highlight: str = "box", tool: str = "proxy",
                                 include_history_row: bool = True,
                                 viewport_height: int = 640, viewport_width: int = 0,
                                 scale: float = 2.5, note: str = "", finding_id: str = "",
                                 step: str = "", auto_redact: bool = False,
                                 template: str = "", redact: str = "",
                                 hide_groups: list[str] | None = None,
                                 hide_headers: list[str] | None = None,
                                 redact_headers: list[str] | None = None,
                                 redact_query: list[str] | None = None,
                                 redact_body_fields: list[str] | None = None,
                                 redact_glyph: str = "",
                                 view: str = "", theme: str = "", size: str = "",
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
            proxy_history_index: get_proxy_history index of the entry to render
                (proxied traffic). Omit when send_ref is given.
            send_ref: a Praetor send handle ('send-N') from send_raw_request — renders
                that stored request/response (non-proxied Logger/Repeater evidence).
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
            auto_redact: OCR-detect secrets and write a pixel-mosaicked twin
                (post-capture). Prefer render-time `redact=` below — it strips the
                secret BEFORE the pixels, so it cannot miss like OCR can.
            template: a saved preset of the redaction/appearance knobs below
                ('defaults', 'clean', 'report-a4', 'empty', or a user template).
                Explicit args override the template. See screenshot_template.
            redact: render-time redaction (deterministic, in the extension).
                '' / 'off' (default) = none; 'defaults'/'on' = the safe secret set
                (cookies, Authorization, API keys, tokens, JWTs, secret query/body
                fields); 'all' = defaults + hide every noise-header group. Keeps the
                reader's structure (cookie names, auth scheme) and hides only values.
            hide_groups: remove noisy header groups — 'browser','caching','cors',
                'security','tracing','all'. Cleans the shot for a report.
            hide_headers: extra header names to remove entirely.
            redact_headers: extra header names whose value to redact.
            redact_query: extra URL query-param names whose value to redact.
            redact_body_fields: extra JSON/form field names whose value to redact.
            redact_glyph: replacement text for redacted values (default █ blocks).
            view: 'raw' (default, on-the-wire bytes) or 'pretty' (reformatted
                JSON/HTML/XML — more readable for a report).
            size: page preset — 'a4','letter','fit' — sizing the viewport. Overrides
                viewport_width/height when set.
            theme: 'light' or 'dark'. Best-effort; the editor follows Burp's theme,
                so an explicit theme is not guaranteed.
            attach: which twin to link to finding_id — 'auto'/'naked'/'none'.
        """
        send_ref = send_ref.strip()
        if not send_ref and proxy_history_index < 0:
            return {"error": "pass proxy_history_index >= 0, or send_ref for a "
                             "Praetor-sent request (Logger/Repeater evidence)"}
        # Source detail: a stored Praetor send, or a proxy-history entry.
        detail_path = (f"/api/http/stored/{send_ref}" if send_ref
                       else f"/api/proxy/history/{proxy_history_index}")
        row_index = 0 if send_ref else proxy_history_index
        w = which.strip().lower()
        which_l = "request" if w.startswith("req") else ("response" if w.startswith("res") else "both")
        # Scan the response for the keyword (richest evidence) unless request-only.
        scan_side = "request" if which_l == "request" else "response"
        # Fetch the entry detail if we need it — to auto-pick the keyword and/or to
        # draw the tool context row on top.
        detail = None
        if not search.strip() or include_history_row:
            detail = await client.get(detail_path)
            if isinstance(detail, dict) and "error" in detail:
                return detail
        term, reason = search.strip(), "explicit"
        if not term:
            from praetor.tools._evidence_keywords import pick_search_term
            term, reason = pick_search_term(
                _scan_text(detail, scan_side), payload, tuple(keywords or ()))
        layout_l = "stacked" if layout.strip().lower().startswith("stack") else "side"

        # Resolve redaction + appearance from a template, with explicit args winning.
        from . import _templates
        cfg = _templates.expand(template, {
            "redact": redact, "hide_groups": hide_groups,
            "hide_headers": hide_headers, "redact_headers": redact_headers,
            "redact_query": redact_query, "redact_body_fields": redact_body_fields,
            "redact_glyph": redact_glyph, "view": view, "theme": theme, "size": size,
        })
        # A page preset sizes the viewport (handler clamps).
        pw, ph = _size_preset(str(cfg.get("size", "")))
        if ph:
            viewport_height = ph
        if pw:
            viewport_width = pw

        payload_json = {
            "which": which_l, "layout": layout_l,
            "search": term, "height": viewport_height, "scale": scale,
        }
        # Render-time redaction + appearance → handler.
        rv = str(cfg.get("redact", "")).strip().lower()
        if rv in ("defaults", "on", "true", "1", "yes", "all"):
            payload_json["redact"] = True
        hide_groups_eff = list(cfg.get("hide_groups") or [])
        if rv == "all" and "all" not in hide_groups_eff:
            hide_groups_eff.append("all")
        if hide_groups_eff:
            payload_json["hide_groups"] = hide_groups_eff
        for k in ("redact_headers", "hide_headers", "redact_query", "redact_body_fields"):
            if cfg.get(k):
                payload_json[k] = list(cfg[k])
        if cfg.get("redact_glyph"):
            payload_json["redact_glyph"] = cfg["redact_glyph"]
        view_eff = str(cfg.get("view", "")).strip().lower()
        if view_eff in ("raw", "pretty"):
            payload_json["view"] = view_eff
        theme_eff = str(cfg.get("theme", "")).strip().lower()
        if theme_eff in ("light", "dark"):
            payload_json["theme"] = theme_eff
        if send_ref:
            payload_json["send_ref"] = send_ref
        else:
            payload_json["proxy_index"] = proxy_history_index
        if viewport_width > 0:   # 0 = let the handler auto-size (1600 side / 1000 else)
            payload_json["width"] = viewport_width
        data = await client.post("/api/ui/message-screenshot", json=payload_json)
        if isinstance(data, dict) and "error" in data:
            return data
        name_hint = _descriptive_base(detail, which_l) if isinstance(detail, dict) else ""
        out = _save_shot(data, domain, f"msg-{which_l}", note, finding_id, step, name_hint)
        if "error" in out:
            return out
        out["which"] = data.get("which", which_l)
        out["layout"] = data.get("layout", layout_l)
        out["search"] = data.get("search", term)
        out["search_reason"] = reason if term else "none_matched"
        out["engine"] = data.get("engine", "")
        # True when the extension stripped secrets at render time (safe shot).
        out["render_redacted"] = bool(data.get("redacted", False))
        if view_eff in ("raw", "pretty"):
            out["view"] = data.get("view", view_eff)
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
                prepend_history_header, out["saved"], detail, row_index,
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
