"""Encoding chain and auto-decode tools — pure Python, no Burp API needed."""

import base64
import html
import re
import urllib.parse

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP):

    @mcp.tool()
    async def transform_chain(
        input_text: str,
        operations: list[str],
    ) -> str:
        """Apply multiple encoding/decoding operations in sequence.

        Args:
            input_text: Starting text
            operations: Ordered list of operations to chain
        """
        if not operations:
            return "Error: No operations specified"

        steps: list[str] = []
        current = input_text
        steps.append(f"[input] {current}")

        for i, op in enumerate(operations, 1):
            try:
                current = _apply_operation(current, op)
                steps.append(f"[{i}. {op}] {current}")
            except Exception as e:
                steps.append(f"[{i}. {op}] ERROR: {e}")
                break

        return "\n→ ".join(steps)

    @mcp.tool()
    async def smart_decode(
        input_text: str,
        max_rounds: int = 5,
    ) -> str:
        """Auto-detect encoding and recursively decode until plaintext is reached.

        Args:
            input_text: Encoded text to decode
            max_rounds: Maximum decoding iterations (default 5)
        """
        steps: list[str] = []
        current = input_text
        steps.append(f"[input] {current}")

        for round_num in range(1, max_rounds + 1):
            encoding = _detect_primary_encoding(current)
            if encoding is None:
                steps.append(f"[round {round_num}] plaintext reached — stopping")
                break

            try:
                decoded = _apply_operation(current, encoding)
            except Exception as e:
                steps.append(f"[round {round_num}] {encoding} decode failed: {e} — stopping")
                break

            if decoded == current:
                steps.append(f"[round {round_num}] no change after {encoding} — stopping")
                break

            steps.append(f"[round {round_num}: {encoding}] {decoded}")
            current = decoded
        else:
            steps.append(f"[max rounds ({max_rounds}) reached]")

        return "\n→ ".join(steps)

    @mcp.tool()
    async def detect_encoding(input_text: str) -> str:
        """Detect what encoding(s) are applied to the given text.

        Args:
            input_text: Text to analyze
        """
        results: list[str] = []

        # JWT check (3 dot-separated base64url parts)
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$')
        if jwt_pattern.match(input_text):
            results.append("JWT token — HIGH confidence")

        # Double URL encoding: %25XX pattern
        double_url = re.findall(r'%25[0-9A-Fa-f]{2}', input_text)
        if double_url:
            pct = min(len(double_url) * 15, 100)
            results.append(f"Double URL encoding — {'HIGH' if pct > 50 else 'MEDIUM'} confidence ({len(double_url)} patterns)")

        # URL encoding: %XX pattern (but not %25 which is double)
        url_matches = re.findall(r'%(?!25)[0-9A-Fa-f]{2}', input_text)
        if url_matches:
            pct = min(len(url_matches) * 10, 100)
            results.append(f"URL encoding — {'HIGH' if pct > 50 else 'MEDIUM'} confidence ({len(url_matches)} encoded chars)")

        # Base64
        stripped = input_text.strip()
        if len(stripped) >= 4 and re.match(r'^[A-Za-z0-9+/=]+$', stripped):
            padding_ok = len(stripped.rstrip('=')) % 4 in (0, 2, 3)
            if padding_ok:
                try:
                    padded = stripped + '=' * (4 - len(stripped) % 4) if len(stripped) % 4 else stripped
                    decoded = base64.b64decode(padded)
                    # Check if decoded content is mostly printable
                    printable = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
                    ratio = printable / len(decoded) if decoded else 0
                    if ratio > 0.7:
                        results.append(f"Base64 — HIGH confidence (decodes to {ratio:.0%} printable text)")
                    elif ratio > 0.3:
                        results.append(f"Base64 — MEDIUM confidence (decodes to {ratio:.0%} printable)")
                    else:
                        results.append("Base64 — LOW confidence (decoded content is mostly binary)")
                except Exception:
                    pass

        # Hex encoding
        if len(stripped) >= 4 and len(stripped) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', stripped):
            try:
                decoded = bytes.fromhex(stripped)
                printable = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
                ratio = printable / len(decoded) if decoded else 0
                if ratio > 0.7:
                    results.append(f"Hex encoding — HIGH confidence (decodes to {ratio:.0%} printable)")
                else:
                    results.append(f"Hex encoding — LOW confidence ({ratio:.0%} printable)")
            except Exception:
                pass

        # HTML entities
        html_named = re.findall(r'&[a-zA-Z]+;', input_text)
        html_numeric = re.findall(r'&#[0-9]+;', input_text)
        html_hex = re.findall(r'&#x[0-9a-fA-F]+;', input_text)
        html_total = len(html_named) + len(html_numeric) + len(html_hex)
        if html_total > 0:
            results.append(f"HTML entities — {'HIGH' if html_total > 3 else 'MEDIUM'} confidence ({html_total} entities)")

        # Unicode escapes
        unicode_matches = re.findall(r'\\u[0-9a-fA-F]{4}', input_text)
        if unicode_matches:
            results.append(f"Unicode escapes — HIGH confidence ({len(unicode_matches)} sequences)")

        # \\xNN hex escapes
        hex_escape_matches = re.findall(r'\\x[0-9a-fA-F]{2}', input_text)
        if hex_escape_matches:
            results.append(f"Hex escapes (\\\\xNN) — HIGH confidence ({len(hex_escape_matches)} sequences)")

        if not results:
            results.append("No encoding detected — likely plaintext")

        header = f"Input: {input_text[:100]}{'...' if len(input_text) > 100 else ''}\n"
        return header + "\n".join(f"  - {r}" for r in results)


# ── Operation implementations ──────────────────────────────────────

def _apply_operation(text: str, op: str) -> str:
    """Apply a single encoding/decoding operation."""
    match op.lower():
        # Base64
        case "base64_encode":
            return base64.b64encode(text.encode()).decode()
        case "base64_decode":
            padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
            return base64.b64decode(padded).decode(errors="replace")

        # URL encoding
        case "url_encode":
            return urllib.parse.quote(text, safe="")
        case "url_decode":
            return urllib.parse.unquote(text)
        case "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")

        # HTML encoding
        case "html_encode":
            return html.escape(text)
        case "html_decode":
            return html.unescape(text)

        # Hex encoding
        case "hex_encode":
            return text.encode().hex()
        case "hex_decode":
            return bytes.fromhex(text).decode(errors="replace")

        # ASCII hex for exploit payloads
        case "ascii_hex":
            return "".join(f"\\x{b:02x}" for b in text.encode())

        # Unicode
        case "unicode_escape":
            return text.encode("unicode_escape").decode()
        case "unicode_unescape":
            return text.encode().decode("unicode_escape")

        # String transforms
        case "reverse":
            return text[::-1]
        case "lowercase":
            return text.lower()
        case "uppercase":
            return text.upper()

        case _:
            raise ValueError(
                f"Unknown operation: {op}. Available: base64_encode, base64_decode, "
                "url_encode, url_decode, double_url_encode, html_encode, html_decode, "
                "hex_encode, hex_decode, unicode_escape, unicode_unescape, ascii_hex, "
                "reverse, lowercase, uppercase"
            )


def _detect_primary_encoding(text: str) -> str | None:
    """Detect the most likely single encoding applied to the text."""
    stripped = text.strip()
    if not stripped:
        return None

    # URL encoding (highest priority — most common in web payloads)
    if re.search(r'%[0-9A-Fa-f]{2}', stripped):
        return "url_decode"

    # HTML entities
    if re.search(r'&(?:[a-zA-Z]+|#[0-9]+|#x[0-9a-fA-F]+);', stripped):
        return "html_decode"

    # Unicode escapes
    if re.search(r'\\u[0-9a-fA-F]{4}', stripped):
        return "unicode_unescape"

    # Base64 (check after URL/HTML since those are more specific)
    if len(stripped) >= 4 and re.match(r'^[A-Za-z0-9+/=]+$', stripped):
        remainder = len(stripped.rstrip('=')) % 4
        if remainder in (0, 2, 3):
            try:
                padded = stripped + '=' * (4 - len(stripped) % 4) if len(stripped) % 4 else stripped
                decoded = base64.b64decode(padded)
                printable = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
                if len(decoded) > 0 and printable / len(decoded) > 0.5:
                    return "base64_decode"
            except Exception:
                pass

    # Hex encoding (even length, all hex chars, reasonable length)
    if (len(stripped) >= 4
            and len(stripped) % 2 == 0
            and re.match(r'^[0-9a-fA-F]+$', stripped)):
        try:
            decoded = bytes.fromhex(stripped)
            printable = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
            if len(decoded) > 0 and printable / len(decoded) > 0.5:
                return "hex_decode"
        except Exception:
            pass

    return None
