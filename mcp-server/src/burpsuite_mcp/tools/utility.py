"""Encoding/decoding utility tools for pentesting - no Burp API needed."""

import base64
import html
import json
import urllib.parse
from hashlib import md5, sha1, sha256

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP):

    @mcp.tool()
    async def decode_encode(
        input_text: str,
        operation: str,
    ) -> str:
        """Encode or decode text using common pentesting encodings.
        Useful for crafting payloads, decoding tokens, and data transformation.

        Operations:
        - base64_encode, base64_decode
        - url_encode, url_decode
        - html_encode, html_decode
        - hex_encode, hex_decode
        - jwt_decode (decode JWT token parts without verification)
        - unicode_escape, unicode_unescape
        - md5, sha1, sha256 (hash, one-way)
        - double_url_encode (for WAF bypass)
        - ascii_hex (convert to \\xNN format for exploit payloads)

        Args:
            input_text: The text to encode/decode
            operation: The operation to perform (e.g. 'base64_encode')
        """
        try:
            result = _perform_operation(input_text, operation)
            return f"[{operation}]\nInput:  {input_text}\nOutput: {result}"
        except Exception as e:
            return f"Error in {operation}: {e}"


def _perform_operation(text: str, op: str) -> str:
    match op.lower():
        # Base64
        case "base64_encode" | "b64e":
            return base64.b64encode(text.encode()).decode()
        case "base64_decode" | "b64d":
            # Handle padding
            padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
            return base64.b64decode(padded).decode(errors="replace")

        # URL encoding
        case "url_encode" | "urle":
            return urllib.parse.quote(text, safe="")
        case "url_decode" | "urld":
            return urllib.parse.unquote(text)
        case "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")

        # HTML encoding
        case "html_encode" | "htmle":
            return html.escape(text)
        case "html_decode" | "htmld":
            return html.unescape(text)

        # Hex encoding
        case "hex_encode" | "hexe":
            return text.encode().hex()
        case "hex_decode" | "hexd":
            return bytes.fromhex(text).decode(errors="replace")

        # ASCII hex for payloads
        case "ascii_hex":
            return "".join(f"\\x{b:02x}" for b in text.encode())

        # Unicode
        case "unicode_escape":
            return text.encode("unicode_escape").decode()
        case "unicode_unescape":
            return text.encode().decode("unicode_escape")

        # JWT decode
        case "jwt_decode" | "jwt":
            return _decode_jwt(text)

        # Hashes
        case "md5":
            return md5(text.encode()).hexdigest()
        case "sha1":
            return sha1(text.encode()).hexdigest()
        case "sha256":
            return sha256(text.encode()).hexdigest()

        case _:
            return f"Unknown operation: {op}. Available: base64_encode, base64_decode, url_encode, url_decode, html_encode, html_decode, hex_encode, hex_decode, jwt_decode, md5, sha1, sha256, double_url_encode, ascii_hex, unicode_escape, unicode_unescape"


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
