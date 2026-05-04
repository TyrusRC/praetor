"""build_target_header_profile + get_target_headers."""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._header_profile import normalize_headers, score_header_set
from ._internals import _atomic_write_json, _ensure_dir, _intel_path


def register(mcp: FastMCP):

    @mcp.tool()
    async def build_target_header_profile(
        domain: str,
        sample_size: int = 50,
        force: bool = False,
    ) -> str:
        """Build a realistic-client header profile from proxy history for WAF-safe fresh requests.

        Args:
            domain: Target domain
            sample_size: Recent proxy history entries to scan (default 50)
            force: Rebuild even if profile already exists
        """
        path = _ensure_dir(domain) / "profile.json"
        existing = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                existing = {}

        if not force and existing.get("realistic_headers"):
            built_idx = existing.get("header_profile_built_from_index", "?")
            built_at = existing.get("header_profile_built_at", "?")
            return (
                f"Header profile already exists for {domain} "
                f"(source index {built_idx}, built {built_at}). "
                "Pass force=True to rebuild. Read it via get_target_headers(domain)."
            )

        history = await client.get(
            "/api/proxy/history",
            params={"limit": sample_size, "host": domain},
        )
        if "error" in history:
            return f"Error reading proxy history: {history['error']}"

        items = history.get("history", []) or history.get("items", [])
        if not items:
            return (
                f"No proxy-history entries for {domain}. Browse the target "
                "first (browser_crawl, or visit pages through the Burp proxy), "
                "then re-run this."
            )

        best_idx = -1
        best_score = -10**6
        best_headers: list[dict] = []
        for item in items:
            idx = item.get("index", -1)
            req = item.get("request") or {}
            headers = req.get("headers") or item.get("request_headers") or []
            if not isinstance(headers, list) or not headers:
                detail = await client.get(f"/api/proxy/history/{idx}")
                if "error" in detail:
                    continue
                headers = detail.get("request_headers") or detail.get("headers") or []
            if not headers:
                continue
            score = score_header_set(headers)
            if score > best_score:
                best_score = score
                best_idx = idx
                best_headers = headers

        if not best_headers:
            return (
                f"Could not extract a usable header set from {len(items)} "
                f"history entries for {domain}. Try a higher sample_size, or "
                "browse a real page (e.g. /login) through the Burp proxy first."
            )

        cleaned = normalize_headers(best_headers)
        ua = cleaned.get("User-Agent") or cleaned.get("user-agent") or "(none)"

        existing["realistic_headers"] = cleaned
        existing["header_profile_built_from_index"] = best_idx
        existing["header_profile_built_at"] = datetime.now(timezone.utc).isoformat()
        existing["header_profile_score"] = best_score
        _atomic_write_json(path, existing)

        lines = [
            f"Header profile saved for {domain}",
            f"  Source proxy-history index: {best_idx}  (score: {best_score})",
            f"  Headers captured: {len(cleaned)}",
            f"  User-Agent: {ua[:120]}",
            "",
            "Pass to curl_request: headers=<get_target_headers(domain)>",
        ]
        return "\n".join(lines)

    @mcp.tool()
    async def get_target_headers(domain: str, auto_build: bool = True) -> str:
        """Return the realistic-client header dict for a domain.

        Args:
            domain: Target domain
            auto_build: Build profile on-demand if missing (default True)
        """
        path = _intel_path(domain) / "profile.json"
        profile: dict = {}
        if path.exists():
            try:
                profile = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                profile = {}

        headers = profile.get("realistic_headers") or {}

        if not headers and auto_build:
            build_msg = await build_target_header_profile(domain=domain)
            try:
                profile = json.loads(path.read_text()) if path.exists() else {}
            except (json.JSONDecodeError, OSError):
                profile = {}
            headers = profile.get("realistic_headers") or {}
            if not headers:
                return f"No header profile for {domain}. {build_msg}"

        if not headers:
            return (
                f"No header profile for {domain}. "
                "Call build_target_header_profile(domain) after browsing "
                "the target through the Burp proxy."
            )

        out = {
            "domain": domain,
            "source_index": profile.get("header_profile_built_from_index"),
            "built_at": profile.get("header_profile_built_at"),
            "headers": headers,
        }
        return json.dumps(out, indent=2)
