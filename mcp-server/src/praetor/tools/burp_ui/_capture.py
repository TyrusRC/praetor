"""burp_screenshot — full-window Burp GUI capture for report evidence."""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._shared import _caption, _pick_attach, _run_auto_redact, _save_shot


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def burp_screenshot(domain: str = "", tab: str = "", subtab: str = "",
                              note: str = "", finding_id: str = "", step: str = "",
                              scale: float = 2.0, banner: bool = False,
                              trademark: str = "", click_button: str = "",
                              select_row: str = "", select_url: str = "",
                              select_proxy_index: int = -1, restore: bool = True,
                              auto_redact: bool = False, attach: str = "auto") -> dict:
        """Screenshot the Burp window for evidence — optionally a named tab/sub-tab/row.

        Brings `tab` (proxy/repeater/intruder/organizer/logger/target/dashboard) and
        nested `subtab` to front before capturing (case-insensitive; empty = current
        view). `click_button='<label>'` clicks a real Burp Swing button first — NOT
        Repeater's custom 'Send' (fire that via repeater_resend/curl_request, whose
        parsed response is the evidence). Select ONE request by identity, not a
        Praetor index (it diverges from Burp's "#"): prefer `select_url='<host/URL
        substring>'`, else `select_proxy_index=<get_proxy_history N>`, else
        `select_row='<#>'`/'last'. Saves a PNG under .burp-intel/<domain>/screenshots/;
        `finding_id` attaches it (renders in report + PoC bundle). NON-DISRUPTIVE by
        default (`restore=True` snapshots+restores the operator's view; a button click
        is not undone). `auto_redact=True` writes a pixel-mosaicked twin; `attach='auto'`
        ships the redacted twin so secrets stay out of the deliverable. SENSITIVE:
        captures the WHOLE window (may show unrelated secrets/hosts) — prefer a specific
        tab and redact before shipping. Requires Burp GUI.
        Full nav / click / selector / redaction reference: get_skill('evidence-and-tabs').

        Args:
            domain: target the shot belongs to (its screenshots dir). Empty -> _burp.
            tab: top-level Burp tab to bring to front (proxy/repeater/...); empty = current.
            subtab: nested sub-tab within `tab` (e.g. 'http history').
            select_url: substring of the request (host/method/URL) to select its row.
            select_proxy_index: a get_proxy_history index, matched by resolved URL (not "#").
            select_row: Burp "#" value off the table, or 'last'/'newest'.
            click_button: label of a Burp Swing button to click before capture.
            note: short caption — finding caption + filename slug (+ footer if banner).
            finding_id: optional saved-finding id to attach the shot to.
            step: PoC step label (ordered in the report; footer text if banner on).
            scale: render scale (default 2×; capped so the long side stays ~2K).
            banner: append a footer caption strip below the shot (ask first; default off).
            trademark: optional brand text, right side of the footer (implies banner).
            auto_redact: OCR-detect secrets and write a pixel-mosaicked redacted twin.
            attach: which twin to link to finding_id — 'auto' (redacted if present,
                else naked), 'naked', or 'none'. Default 'auto' keeps secrets out.
        """
        label = _caption(step, note) if (banner or trademark.strip()) else ""
        params = {"scale": str(scale)}
        if tab.strip():
            params["tab"] = tab
        if subtab.strip():
            params["subtab"] = subtab
        if click_button.strip():
            params["click_button"] = click_button.strip()
        if select_row.strip():
            params["select_row"] = select_row.strip()
        # Row-by-request-identity: an explicit URL substring, or a proxy-history
        # index resolved server-side to that request's URL path. Either becomes a
        # text needle the extension matches against the table (see docstring).
        needle = select_url.strip()
        if not needle and select_proxy_index >= 0:
            detail = await client.get(f"/api/proxy/history/{select_proxy_index}")
            if isinstance(detail, dict) and "error" not in detail:
                u = urlparse(str(detail.get("url", "")))
                # host + path: the path alone repeats across hosts (and "/" matches
                # every row), so AND the host in to pin the exact request.
                needle = f"{u.netloc} {u.path}".strip()
        if needle:
            params["select_match"] = needle
        if not restore:
            params["restore"] = "false"
        if label:
            params["label"] = label
        if trademark.strip():
            params["trademark"] = trademark
        data = await client.get("/api/ui/screenshot", params=params)
        if isinstance(data, dict) and "error" in data:
            return data
        out = _save_shot(data, domain, tab, note, finding_id, step)
        if "error" not in out:
            # Which tab (and nested sub-tab) the extension actually brought to
            # front — empty if the name didn't match (the shot is the prior tab).
            out["selected_tab"] = data.get("selected_tab", "")
            out["selected_subtab"] = data.get("selected_subtab", "")
            out["clicked_button"] = data.get("clicked_button", "")
            out["selected_row"] = data.get("selected_row", -1)
            out["selected_match"] = data.get("selected_match", "")
            # Auto-redact: OCR-detect secrets and save a redacted twin. The naked
            # shot (out['saved']) stays; the operator picks which goes in the report.
            if auto_redact:
                r = await _run_auto_redact(out["saved"])
                out["redacted"] = r.get("redacted", "")
                out["redacted_regions"] = r.get("regions", 0)
                if "error" in r:
                    out["redact_error"] = r["error"]
            # Which twin gets attached to the finding (⇒ ships in report + PoC
            # bundle). 'auto' ships the REDACTED twin when one exists so a secret
            # never reaches the deliverable; 'naked' forces the raw shot; 'none'
            # skips attach.
            attach_path = _pick_attach(out["saved"], out.get("redacted", ""), attach)
            if finding_id and domain and attach_path:
                from praetor.tools.notes._screenshot_attach import _attach_screenshot
                # off-thread: the attach takes a blocking flock on findings.json.
                out["attached"] = await asyncio.to_thread(
                    _attach_screenshot, domain, finding_id, attach_path, note, step)
                out["attached_file"] = Path(attach_path).name
        return out

