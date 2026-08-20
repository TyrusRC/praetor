"""detect_mcp_invisible_unicode — D1 (Spec D, 2026-07-23).

Invisible-unicode concealment in MCP tool metadata (arXiv 2607.05744; MCPTox
ASR up to 72.8%). TAG-block (U+E0000-E007F), zero-width, and bidi-override
codepoints are invisible in the human approval view but delivered verbatim to
the consuming model — defeating both human review and text filters.

Static detector: no destructive payload; scans a provided tool list, or fetches
a live tools/list through Burp when given a server URL.

Returns VerdictResult.
"""

from __future__ import annotations

import json
import unicodedata

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing._verdict import make_verdict, error_verdict


# Concealment codepoint ranges. Kept explicit for auditability.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_BIDI_OVERRIDE = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def _category(cp: int) -> str | None:
    if 0xE0000 <= cp <= 0xE007F:
        return "tag_block"
    if cp in _ZERO_WIDTH:
        return "zero_width"
    if cp in _BIDI_OVERRIDE:
        return "bidi_override"
    return None


def find_hidden_unicode(text: str) -> list[dict]:
    """Return one hit per concealment codepoint in `text`."""
    hits: list[dict] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        cat = _category(cp)
        if cat is None:
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "<unnamed>"
        hits.append({
            "index": i,
            "codepoint": f"U+{cp:04X}",
            "category": cat,
            "char_name": name,
        })
    return hits


def scan_tool_metadata(tools: list[dict]) -> dict:
    """Scan MCP tool descriptors. name/description = model-visible channel;
    inputSchema = secondary channel."""
    model_visible: list[dict] = []
    schema_hits: list[dict] = []
    flagged: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("name", ""))
        vis = find_hidden_unicode(tname) + find_hidden_unicode(
            str(t.get("description", "")))
        sch = find_hidden_unicode(json.dumps(t.get("inputSchema", {}),
                                             ensure_ascii=False))
        if vis:
            model_visible.extend({**h, "tool": tname, "field": "name/description"}
                                 for h in vis)
        if sch:
            schema_hits.extend({**h, "tool": tname, "field": "inputSchema"}
                               for h in sch)
        if vis or sch:
            flagged.append(tname)
    return {
        "model_visible_hits": model_visible,
        "schema_hits": schema_hits,
        "tools_flagged": flagged,
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def detect_mcp_invisible_unicode(
        tools_json: str = "",
        server_url: str = "",
        session: str = "",
        timeout: int = 15,
    ) -> dict:
        """Detect invisible-unicode concealment in MCP tool metadata (D1).

        Provide EITHER `tools_json` (a JSON array of MCP tool descriptors, or a
        tools/list response object with a `tools` field, e.g. from
        `enumerate_mcp_server`) OR `server_url` to fetch tools/list live.

        CONFIRMED when concealment codepoints (TAG-block / zero-width / bidi)
        appear in a model-visible field (name/description); SUSPECTED when only
        inputSchema carries them.

        Args:
            tools_json: JSON array/object of MCP tool descriptors.
            server_url: MCP server endpoint to fetch tools/list from.
            session: optional session name (for authenticated fetch).
            timeout: per-fetch timeout (s).

        Returns: VerdictResult.
        """
        tools: list = []
        logger_indices: list[int] = []

        if tools_json:
            try:
                parsed = json.loads(tools_json)
            except json.JSONDecodeError as e:
                return error_verdict(f"tools_json parse error: {e}",
                                     vuln_type="mcp_invisible_unicode")
            if isinstance(parsed, dict):
                tools = parsed.get("tools") or parsed.get("result", {}).get("tools", [])
            else:
                tools = parsed
        elif server_url:
            resp = await _fetch_tools(server_url, session, timeout)
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            body = resp.get("response_body") or ""
            try:
                obj = json.loads(body)
                tools = (obj.get("result", {}).get("tools", [])
                         if isinstance(obj, dict) else []) or (
                    obj.get("tools", []) if isinstance(obj, dict) else [])
            except (json.JSONDecodeError, AttributeError):
                return error_verdict(
                    "server_url did not return a parseable tools/list",
                    vuln_type="mcp_invisible_unicode")
        else:
            return error_verdict("provide tools_json or server_url",
                                 vuln_type="mcp_invisible_unicode")

        if not isinstance(tools, list) or not tools:
            return make_verdict(
                "FAILED", 0.10, "No MCP tools to scan.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                summary="FAILED — no tools scanned")

        r = scan_tool_metadata(tools)
        if r["model_visible_hits"]:
            return make_verdict(
                "CONFIRMED", 0.88,
                f"{len(r['model_visible_hits'])} concealment codepoint(s) in "
                f"model-visible tool metadata across {len(r['tools_flagged'])} "
                f"tool(s): {r['tools_flagged'][:5]}. Invisible to human review, "
                "delivered verbatim to the consuming model.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                details=r,
                summary=f"CONFIRMED invisible-unicode in {r['tools_flagged'][:3]}")
        if r["schema_hits"]:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"{len(r['schema_hits'])} concealment codepoint(s) in tool "
                "inputSchema only (secondary channel). Manual review advised.",
                vuln_type="mcp_invisible_unicode",
                logger_indices=logger_indices,
                details=r,
                summary="SUSPECTED invisible-unicode in inputSchema")
        return make_verdict(
            "FAILED", 0.15,
            f"No concealment codepoints across {len(tools)} tool(s).",
            vuln_type="mcp_invisible_unicode",
            logger_indices=logger_indices,
            summary="FAILED — tool metadata clean")


async def _fetch_tools(server_url: str, session: str, timeout: int) -> dict:
    payload = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    headers = [{"name": "Content-Type", "value": "application/json"}]
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "POST", "url": server_url,
            "headers": headers, "body": payload})
    return await client.post("/api/http/curl", json={
        "url": server_url, "method": "POST", "headers": headers,
        "body": payload, "timeout": timeout})
