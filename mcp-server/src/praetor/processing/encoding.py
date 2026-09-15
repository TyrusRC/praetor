"""Shared encode/decode operations used by both transform.py and utility.py.

Centralized so the same operator parsing the same input always produces the
same output regardless of which entrypoint they hit.
"""

import base64
import hashlib
import html
import urllib.parse


def apply_operation(text: str, op: str) -> str:
    """Apply a single encode/decode op. Raises ValueError on unknown op."""
    # Parametrized ops carry a value after the first colon. The keyword is
    # case-insensitive; the value is preserved verbatim (it may itself contain
    # colons, e.g. "prefix:carlos:" to build a "user:hash" token). Handled
    # before the match so a colon in the value never breaks op lookup.
    kind, sep, value = op.partition(":")
    if sep and kind.lower() in ("prefix", "suffix"):
        return value + text if kind.lower() == "prefix" else text + value

    match op.lower():
        # Hashes: hex digest of the UTF-8 bytes. These build predictable
        # session/token values (e.g. base64(username:md5(password))) — chain
        # as ["md5", "prefix:user:", "base64_encode"].
        case "md5":
            return hashlib.md5(text.encode()).hexdigest()
        case "sha1":
            return hashlib.sha1(text.encode()).hexdigest()
        case "sha256":
            return hashlib.sha256(text.encode()).hexdigest()
        case "base64_encode" | "b64e":
            return base64.b64encode(text.encode()).decode()
        case "base64_decode" | "b64d":
            padded = _pad_base64(text)
            return base64.b64decode(padded).decode(errors="replace")
        case "url_encode" | "urle":
            return urllib.parse.quote(text, safe="")
        case "url_decode" | "urld":
            return urllib.parse.unquote(text)
        case "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")
        case "html_encode" | "htmle":
            return html.escape(text)
        case "html_decode" | "htmld":
            return html.unescape(text)
        case "hex_entities":
            # Every char -> &#xNN; XML numeric entity. Unlike html_encode
            # (specials only), this hides SQL/XSS keywords entirely, so a WAF
            # can't keyword-match while an XML/HTML parser still reconstructs
            # the payload. Reverse with html_decode.
            return "".join(f"&#x{ord(c):x};" for c in text)
        case "dec_entities":
            # Same, decimal form (&#NN;). Reverse with html_decode.
            return "".join(f"&#{ord(c)};" for c in text)
        case "hex_encode" | "hexe":
            return text.encode().hex()
        case "hex_decode" | "hexd":
            return bytes.fromhex(text).decode(errors="replace")
        case "ascii_hex":
            return "".join(f"\\x{b:02x}" for b in text.encode())
        case "unicode_escape":
            return text.encode("unicode_escape").decode()
        case "unicode_unescape":
            return text.encode().decode("unicode_escape")
        case "reverse":
            return text[::-1]
        case "lowercase":
            return text.lower()
        case "uppercase":
            return text.upper()
        case _:
            raise ValueError(f"Unknown operation: {op}")


def _pad_base64(text: str) -> str:
    """Add base64 padding when missing. Idempotent."""
    rem = len(text) % 4
    if rem == 0:
        return text
    return text + "=" * (4 - rem)


# Public alias — same semantics, different name in transform.py historically.
def pad_base64(text: str) -> str:
    return _pad_base64(text)


SHARED_OPS = (
    "base64_encode", "base64_decode",
    "url_encode", "url_decode", "double_url_encode",
    "html_encode", "html_decode",
    "hex_entities", "dec_entities",
    "hex_encode", "hex_decode",
    "ascii_hex",
    "unicode_escape", "unicode_unescape",
    "reverse", "lowercase", "uppercase",
    "md5", "sha1", "sha256",
    "prefix:<value>", "suffix:<value>",
)
