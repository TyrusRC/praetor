"""Encoding/decoding utility tools for pentesting - no Burp API needed."""

import base64
import html
import json
import urllib.parse
from hashlib import md5, sha1, sha256

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.config import BURP_PROXY_HOST, BURP_PROXY_PORT


def register(mcp: FastMCP):

    @mcp.tool()
    async def audit_recent_traffic(window_seconds: int = 300, expected_min_count: int = 1) -> str:
        """Audit whether recent operations actually routed through Burp.

        Use after running a custom script or batch of curl commands. Counts
        proxy-history entries and compares against `expected_min_count`; if
        the count is below threshold, the script likely bypassed the proxy.
        (Burp's HTTP layer does not expose a stable per-entry timestamp, so
        `window_seconds` is documentary only — surface it in your error
        guidance, not as a precise time filter.)

        Cost class: cheap.

        Args:
            window_seconds: Lookback context for the warning text (no precise filtering)
            expected_min_count: Min proxy-history entries expected for traffic to count as audited
        """
        from burpsuite_mcp import client as _client
        data = await _client.get("/api/proxy/history", params={"limit": 50, "offset": 0})
        if "error" in data:
            return f"Error: {data['error']}"
        items = data.get("items", []) or []
        if not items:
            return (
                f"AUDIT: 0 entries in proxy history at all. Burp may be empty, "
                f"or all recent traffic bypassed the proxy. Check HTTPS_PROXY "
                f"is set (see get_burp_proxy_env)."
            )
        # Heuristic: just count items; the Burp HTTP layer doesn't expose a
        # stable timestamp on every entry. We compare proxy count vs expected.
        total = data.get("total", len(items))
        if len(items) < expected_min_count:
            return (
                f"AUDIT WARNING: only {len(items)} proxy-history entries "
                f"(expected >= {expected_min_count} in last {window_seconds}s). "
                f"Recent script traffic likely bypassed Burp. Set HTTPS_PROXY "
                f"(get_burp_proxy_env) and re-run."
            )
        recent = items[-min(5, len(items)):]
        lines = [
            f"AUDIT OK: proxy history has {total} total entries; recent {len(recent)} sample:",
        ]
        for it in recent:
            lines.append(
                f"  [{it.get('index', '?')}] {it.get('method', '?')} "
                f"{it.get('status_code', '-')} {it.get('url', '?')}"
            )
        lines.append(
            "If your most recent script run is missing from this list, it "
            "bypassed Burp. Set HTTPS_PROXY (get_burp_proxy_env) and re-run."
        )
        return "\n".join(lines)

    @mcp.tool()
    async def get_burp_proxy_env() -> str:
        """Return shell env-var lines + Python snippet to route arbitrary scripts through Burp's proxy.

        Use BEFORE writing any custom Python script (curl/httpx/requests/fetch).
        Routing through Burp ensures every request appears in Proxy history with a
        logger_index — required for save_finding evidence (Rule 26a). Without this,
        scripted findings are unverifiable and will be hard-rejected by assess_finding.
        """
        proxy = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
        return (
            "# Route subprocess / script traffic through Burp:\n"
            f"export HTTPS_PROXY={proxy}\n"
            f"export HTTP_PROXY={proxy}\n"
            "export REQUESTS_CA_BUNDLE=/path/to/burp-ca.pem  # or NO verify for testing\n"
            "\n"
            "# Python (httpx):\n"
            f"client = httpx.AsyncClient(proxy='{proxy}', verify=False)\n"
            "\n"
            "# Python (requests):\n"
            f"requests.get(url, proxies={{'http':'{proxy}','https':'{proxy}'}}, verify=False)\n"
            "\n"
            "# curl:\n"
            f"curl -x {proxy} -k <url>\n"
            "\n"
            "Reminder: prefer concurrent_requests / send_to_intruder_configured / "
            "fuzz_parameter / auto_probe / batch_probe instead of writing a script. "
            "Those are already proxied and produce logger_index for evidence."
        )

    @mcp.tool()
    async def decode_encode(
        input_text: str,
        operation: str,
    ) -> str:
        """Encode or decode text using common pentesting encodings.

        Args:
            input_text: Text to encode/decode
            operation: base64_encode/decode, url_encode/decode, html_encode/decode, hex_encode/decode, jwt_decode, md5, sha1, sha256, double_url_encode, ascii_hex, unicode_escape/unescape
        """
        try:
            result = _perform_operation(input_text, operation)
            return f"[{operation}]\nInput:  {input_text}\nOutput: {result}"
        except Exception as e:
            return f"Error in {operation}: {e}"


def _perform_operation(text: str, op: str) -> str:
    """Encode/decode/hash dispatcher used by decode_encode tool.

    Shared encode/decode ops live in processing/encoding so transform.py
    and this tool can't drift. Hashes and JWT decode are utility-specific.
    """
    op_lower = op.lower()
    if op_lower in ("jwt_decode", "jwt"):
        return _decode_jwt(text)
    if op_lower == "md5":
        return md5(text.encode()).hexdigest()
    if op_lower == "sha1":
        return sha1(text.encode()).hexdigest()
    if op_lower == "sha256":
        return sha256(text.encode()).hexdigest()
    from burpsuite_mcp.processing.encoding import apply_operation, SHARED_OPS
    try:
        return apply_operation(text, op)
    except ValueError:
        return (
            f"Unknown operation: {op}. Available: "
            + ", ".join(SHARED_OPS + ("jwt_decode", "md5", "sha1", "sha256"))
        )


def _decode_jwt(token: str) -> str:
    """Decode JWT token parts without verification."""
    parts = token.split(".")
    if len(parts) < 2:
        return "Invalid JWT: expected at least 2 parts separated by dots"

    lines = []
    labels = ["Header", "Payload", "Signature"]

    for i, part in enumerate(parts):
        label = labels[i] if i < len(labels) else f"Part {i}"
        if i < 2:  # Header and payload are base64
            # Add padding
            padded = part + "=" * (4 - len(part) % 4) if len(part) % 4 else part
            # URL-safe base64
            padded = padded.replace("-", "+").replace("_", "/")
            try:
                decoded = base64.b64decode(padded).decode()
                parsed = json.loads(decoded)
                lines.append(f"--- {label} ---")
                lines.append(json.dumps(parsed, indent=2))
            except Exception:
                lines.append(f"--- {label} (raw) ---")
                lines.append(part)
        else:
            lines.append(f"--- {label} ---")
            lines.append(part)

    return "\n".join(lines)
