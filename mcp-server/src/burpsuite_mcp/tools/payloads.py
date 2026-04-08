"""Context-aware payload lookup from curated knowledge base."""

import json
import urllib.parse
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP


PAYLOADS_DIR = Path(__file__).parent.parent / "payloads"


@lru_cache(maxsize=16)
def _load_payload_file(category: str) -> dict | None:
    """Load and cache a payload JSON file. Cached per category."""
    payload_file = PAYLOADS_DIR / f"{category}.json"
    if not payload_file.exists():
        return None
    try:
        with open(payload_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_payloads(
        category: str,
        context: str = "",
        waf_bypass: bool = False,
        encoding: str = "none",
        limit: int = 20,
        variables: dict | None = None,
    ) -> str:
        """Get advanced payloads for vulnerability testing. Curated from HackTricks,
        PayloadsAllTheThings, and PortSwigger research. Use detect_tech_stack first
        to pick the right context.

        Categories: xss, sqli, ssti, ssrf, command_injection, path_traversal,
                    xxe, auth_bypass, cors, csrf, race_condition, hpp

        Args:
            category: Vulnerability category (e.g. 'xss', 'sqli', 'ssti')
            context: Narrow to specific context (e.g. 'angular', 'mysql', 'jinja2'). Empty = all contexts.
            waf_bypass: If True, only return WAF evasion payloads. If False, return all.
            encoding: Apply encoding - 'none', 'url', 'double_url', 'html', 'unicode'
            limit: Max payloads to return (default 20)
            variables: Template variables to interpolate in payloads (e.g. {"callback": "burpcollaborator.net", "target": "10.0.0.1"})
        """
        data = _load_payload_file(category)
        if data is None:
            available = [f.stem for f in PAYLOADS_DIR.glob("*.json")]
            return f"Unknown category '{category}'. Available: {', '.join(sorted(available))}"

        contexts = data.get("contexts", {})
        if context:
            if context not in contexts:
                available = list(contexts.keys())
                return f"Unknown context '{context}' for {category}. Available: {', '.join(available)}"
            contexts = {context: contexts[context]}

        results = []
        for ctx_name, ctx_data in contexts.items():
            for p in ctx_data.get("payloads", []):
                if waf_bypass and not p.get("waf_bypass"):
                    continue
                results.append({
                    "context": ctx_name,
                    "payload": p["payload"],
                    "description": p.get("description", ""),
                    "waf_bypass": p.get("waf_bypass", False),
                })

        if not results:
            return f"No payloads found for {category}" + (f" context={context}" if context else "") + (" (waf_bypass only)" if waf_bypass else "")

        # Apply template variable interpolation
        if variables:
            for r in results:
                for var_name, var_value in variables.items():
                    r["payload"] = r["payload"].replace("{{" + var_name + "}}", var_value)

        # Apply encoding
        if encoding != "none":
            for r in results:
                r["payload"] = _encode(r["payload"], encoding)

        results = results[:limit]

        filter_desc = f"category={category}"
        if context:
            filter_desc += f", context={context}"
        if waf_bypass:
            filter_desc += ", waf_bypass=true"
        if encoding != "none":
            filter_desc += f", encoding={encoding}"

        lines = [f"Payloads ({filter_desc}) — {len(results)} results:\n"]

        current_ctx = ""
        for i, r in enumerate(results, 1):
            if r["context"] != current_ctx:
                current_ctx = r["context"]
                ctx_desc = contexts.get(current_ctx, {}).get("description", current_ctx)
                lines.append(f"# {ctx_desc}")

            bypass = " [WAF]" if r["waf_bypass"] else ""
            lines.append(f"{i}. {r['payload']}")
            lines.append(f"   {r['description']}{bypass}")

        return "\n".join(lines)


def _encode(payload: str, encoding: str) -> str:
    """Apply encoding to payload."""
    match encoding:
        case "url":
            return urllib.parse.quote(payload, safe="")
        case "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        case "html":
            return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
        case "unicode":
            return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or not c.isalnum() else c for c in payload)
        case _:
            return payload
