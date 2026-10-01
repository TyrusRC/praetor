"""Encoding/decoding utility tools for pentesting - no Burp API needed."""

import base64
import json
import shlex
from hashlib import md5, sha1, sha256

from mcp.server.fastmcp import FastMCP

from praetor.config import BURP_PROXY_HOST, BURP_PROXY_PORT


def _arg(toks: list[str], i: int) -> str:
    return toks[i + 1] if i + 1 < len(toks) else ""


# curl flags that consume the NEXT token but that we don't model (proxy, resolve,
# output, timing) — skip the flag AND its value so they don't get read as the URL.
_CURL_SKIP_VALUE = {
    "-x", "--proxy", "--connect-to", "--resolve", "-o", "--output",
    "-w", "--write-out", "-m", "--max-time", "--retry", "--cacert",
    "-E", "--cert", "--key", "--limit-rate",
}


def _parse_curl(cmd: str) -> dict:
    """Parse a curl command line into {method, url, headers, body} (or {error}).

    shlex-tokenised and NEVER executed. Best-effort over the flags a 'Copy as
    cURL' produces: -X, -H, -d/--data*, -b/--cookie, -A, -e, -u, --url, -G.
    Unmodelled value-flags are skipped; bare valueless flags (-s -k -L -i -v
    --compressed and bundled shorts like -fsSL) are ignored.
    """
    try:
        toks = shlex.split(cmd.strip())
    except ValueError as e:
        return {"error": f"could not tokenise curl command: {e}"}
    if toks and toks[0] == "curl":
        toks = toks[1:]
    method = ""
    url = ""
    headers: dict[str, str] = {}
    data_parts: list[str] = []
    force_get = False
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request"):
            method = _arg(toks, i).upper(); i += 2; continue
        if t in ("-H", "--header"):
            h = _arg(toks, i); i += 2
            if ":" in h:
                k, _, v = h.partition(":")
                headers[k.strip()] = v.strip()
            continue
        if t in ("-d", "--data", "--data-raw", "--data-binary",
                 "--data-ascii", "--data-urlencode"):
            data_parts.append(_arg(toks, i)); i += 2; continue
        if t in ("-b", "--cookie"):
            headers["Cookie"] = _arg(toks, i); i += 2; continue
        if t in ("-A", "--user-agent"):
            headers["User-Agent"] = _arg(toks, i); i += 2; continue
        if t in ("-e", "--referer"):
            headers["Referer"] = _arg(toks, i); i += 2; continue
        if t in ("-u", "--user"):
            cred = _arg(toks, i); i += 2
            headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
            continue
        if t == "--url":
            url = _arg(toks, i); i += 2; continue
        if t in ("-G", "--get"):
            force_get = True; i += 1; continue
        if t in _CURL_SKIP_VALUE:
            i += 2; continue
        if t.startswith("-"):
            i += 1; continue  # valueless flag / bundled shorts
        if not url:
            url = t
        i += 1
    body = "&".join(p for p in data_parts if p)
    if force_get:
        method = "GET"
    elif not method:
        method = "POST" if body else "GET"
    return {"method": method, "url": url, "headers": headers, "body": body}


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
        from praetor import client as _client
        data = await _client.get("/api/proxy/history", params={"limit": 50, "offset": 0})
        if "error" in data:
            return f"Error: {data['error']}"
        items = data.get("items", []) or []
        if not items:
            return (
                "AUDIT: 0 entries in proxy history at all. Burp may be empty, "
                "or all recent traffic bypassed the proxy. Check HTTPS_PROXY "
                "is set (see get_burp_proxy_env)."
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
        proxy_history_index — required for save_finding evidence (Rule 26a). Without this,
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
            "Those are already proxied and produce proxy_history_index for evidence."
        )

    @mcp.tool()
    async def import_curl(curl_command: str) -> str:
        """Parse a cURL command into a request + the Praetor call to replay it (PTK cURL import).

        Paste a `curl ...` line (e.g. the browser Network tab's 'Copy as cURL');
        this tokenises it with shlex — it is NEVER executed — and extracts
        method / url / headers / cookies / body / basic-auth. Returns the parsed
        request and a ready curl_request(...) call that replays it THROUGH Burp
        (so the replay lands in Logger/Proxy history with a citable index). It
        does not send — run the emitted call yourself.

        Args:
            curl_command: the full curl command line (quotes preserved).
        """
        parsed = _parse_curl(curl_command)
        if "error" in parsed:
            return f"Error: {parsed['error']}"
        method, url = parsed["method"], parsed["url"]
        headers, body = parsed["headers"], parsed["body"]
        if not url:
            return "Error: no URL found in the curl command."
        lines = ["Parsed cURL:", f"  {method} {url}"]
        if headers:
            lines.append(f"  headers ({len(headers)}):")
            for k, v in headers.items():
                # shape obviously-sensitive values in the summary (full values
                # still flow into the replay call below, which the agent executes)
                shown = (str(v)[:18] + "…") if k.lower() in ("authorization", "cookie") else v
                lines.append(f"    {k}: {shown}")
        if body:
            lines.append(f"  body ({len(body)}B): {body[:200]}")
        call = f"curl_request(method={method!r}, url={url!r}"
        if headers:
            call += f", headers={headers!r}"
        if body:
            call += f", data={body!r}"
        call += ")"
        lines += ["", "Replay through Burp (run this):", f"  {call}"]
        return "\n".join(lines)

    @mcp.tool()
    async def request_to_curl(index: int) -> str:
        """Export a captured proxy-history request as a copy-paste cURL command (PTK cURL export).

        For any request by proxy-history index — the general-purpose counterpart
        to generate_repro_script (which is finding-scoped). Fetches entry <index>
        and renders a curl that reproduces it.

        Args:
            index: proxy-history index to export.
        """
        from praetor import client
        from praetor.tools.notes._proxy_entry import _normalize_entry
        from praetor.tools.notes.repro_script import _curl_for_request
        detail = await client.get(
            f"/api/proxy/history/{int(index)}", params={"include_body": "true"})
        if "error" in detail:
            return f"Error fetching proxy entry {index}: {detail['error']}"
        return _curl_for_request(_normalize_entry(detail))

    @mcp.tool()
    async def generate_random_string(length: int = 16, charset: str = "alphanumeric") -> str:
        """Generate a cryptographically-random string (PortSwigger-MCP parity).

        Uses `secrets` (CSPRNG) — suitable for nonces, CSRF-token guesses, cache
        busters, boundary markers, unique probe canaries.

        Args:
            length: number of characters (1-4096, default 16).
            charset: alphanumeric (default) | alpha | numeric | hex | ascii | url-safe.
        """
        import secrets
        import string
        sets = {
            "alphanumeric": string.ascii_letters + string.digits,
            "alpha": string.ascii_letters,
            "numeric": string.digits,
            "hex": "0123456789abcdef",
            "ascii": string.ascii_letters + string.digits + string.punctuation,
            "url-safe": string.ascii_letters + string.digits + "-_",
        }
        pool = sets.get((charset or "").lower().strip())
        if not pool:
            return f"Error: unknown charset '{charset}'. Use one of: {', '.join(sets)}."
        n = max(1, min(int(length), 4096))
        return "".join(secrets.choice(pool) for _ in range(n))

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
    from praetor.processing.encoding import apply_operation, SHARED_OPS
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
