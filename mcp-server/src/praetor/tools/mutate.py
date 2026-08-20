"""mutate_payload — generate bypass variants of a seed payload.

Pure-Python primitive used by fuzz_with_feedback and operator-driven
WAF-bypass loops. Twelve mutation classes covering the most productive
filter-evasion grammars in real engagements. No Burp call.

Mutation classes:
    encoding_url        single URL-encode every char
    encoding_double     double URL-encode every char
    encoding_unicode    \\uXXXX escape for ASCII payloads (JS/JSON context)
    encoding_html       HTML entity encode (&#dec; / &#xhex;)
    case_toggle         flip case on each alpha char (SQL/SSTI keywords)
    case_mixed          random-looking case (alternating)
    comment_sql         insert /**/ between SQL tokens
    null_byte           prepend / suffix %00
    crlf                prepend %0d%0a header-break
    whitespace_alt      replace space with tab / %09 / %0c / +
    quote_rotate        swap ' ↔ " ↔ ` ↔ no-quote
    length_pad          prefix junk to push past length matchers
"""

import urllib.parse


def _url_encode_all(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _url_encode_double(s: str) -> str:
    once = "".join(f"%{ord(c):02x}" for c in s)
    return urllib.parse.quote(once, safe="")


def _unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in s)


def _html_entity_decimal(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def _case_toggle(s: str) -> str:
    return "".join(c.lower() if c.isupper() else c.upper() if c.islower() else c for c in s)


def _case_mixed(s: str) -> str:
    out = []
    flip = False
    for c in s:
        if c.isalpha():
            out.append(c.upper() if flip else c.lower())
            flip = not flip
        else:
            out.append(c)
    return "".join(out)


_SQL_KEYWORDS = (
    "select", "union", "from", "where", "and", "or", "insert", "update",
    "delete", "drop", "exec", "sleep", "waitfor", "delay",
)


def _comment_sql(s: str) -> str:
    out = s
    for kw in _SQL_KEYWORDS:
        for variant in (kw, kw.upper()):
            if variant in out:
                spaced = "/**/".join(variant)
                out = out.replace(variant, spaced)
    if out == s and " " in s:
        out = s.replace(" ", "/**/")
    return out


def _null_prefix(s: str) -> str:
    return "%00" + s


def _null_suffix(s: str) -> str:
    return s + "%00"


def _crlf_prefix(s: str) -> str:
    return "%0d%0a" + s


def _whitespace_tab(s: str) -> str:
    return s.replace(" ", "\t")


def _whitespace_plus(s: str) -> str:
    return s.replace(" ", "+")


def _whitespace_url_tab(s: str) -> str:
    return s.replace(" ", "%09")


def _whitespace_formfeed(s: str) -> str:
    return s.replace(" ", "%0c")


def _quote_to_double(s: str) -> str:
    return s.replace("'", '"')


def _quote_to_backtick(s: str) -> str:
    return s.replace("'", "`").replace('"', "`")


def _quote_strip(s: str) -> str:
    return s.replace("'", "").replace('"', "")


def _length_pad(s: str, n: int = 4096) -> str:
    return "A" * n + s


def _length_pad_short(s: str) -> str:
    return "/" * 64 + s


_MUTATORS: dict[str, list] = {
    "encoding_url":     [_url_encode_all],
    "encoding_double":  [_url_encode_double],
    "encoding_unicode": [_unicode_escape],
    "encoding_html":    [_html_entity_decimal, _html_entity_hex],
    "case_toggle":      [_case_toggle],
    "case_mixed":       [_case_mixed],
    "comment_sql":      [_comment_sql],
    "null_byte":        [_null_prefix, _null_suffix],
    "crlf":             [_crlf_prefix],
    "whitespace_alt":   [_whitespace_tab, _whitespace_plus, _whitespace_url_tab, _whitespace_formfeed],
    "quote_rotate":     [_quote_to_double, _quote_to_backtick, _quote_strip],
    "length_pad":       [_length_pad_short, _length_pad],
}


_DEFAULT_CLASSES = (
    "encoding_url",
    "encoding_double",
    "case_toggle",
    "case_mixed",
    "comment_sql",
    "null_byte",
    "whitespace_alt",
    "quote_rotate",
)


def generate_variants(
    payload: str,
    classes: list[str] | None = None,
    count: int = 0,
) -> list[dict]:
    """Generate distinct mutation variants of a payload.

    Returns list of {variant, mutation_class, mutator} dicts, deduped on
    variant string. Order: stable, by class order then mutator order.
    """
    if not payload:
        return []
    selected = classes or list(_DEFAULT_CLASSES)
    seen: set[str] = {payload}
    out: list[dict] = []
    for cls in selected:
        muts = _MUTATORS.get(cls)
        if not muts:
            continue
        for fn in muts:
            try:
                variant = fn(payload)
            except Exception:
                continue
            if not variant or variant in seen:
                continue
            seen.add(variant)
            out.append({
                "variant": variant,
                "mutation_class": cls,
                "mutator": fn.__name__.lstrip("_"),
            })
            if count and len(out) >= count:
                return out
    return out


def register(mcp) -> None:

    @mcp.tool()
    async def mutate_payload(  # cost: free (pure Python)
        payload: str,
        classes: list[str] | None = None,
        count: int = 0,
    ) -> str:
        """Generate bypass variants of a seed payload.

        Pure-Python primitive. Feed the variants into fuzz_with_feedback,
        fuzz_parameter, concurrent_requests, or send_to_intruder_configured.
        Twelve mutation classes available — pass `classes=[]` (omit) for the
        recommended default subset, or list explicit classes to narrow.

        Args:
            payload: Seed payload to mutate.
            classes: Mutation classes. Default subset covers the most productive
                bypasses (url, double-url, case, sql-comment, null, whitespace,
                quote rotation). Available:
                encoding_url, encoding_double, encoding_unicode, encoding_html,
                case_toggle, case_mixed, comment_sql, null_byte, crlf,
                whitespace_alt, quote_rotate, length_pad.
            count: Cap on output (0 = no cap).
        """
        variants = generate_variants(payload, classes=classes, count=count)
        if not variants:
            return f"No variants generated for {payload!r} (empty seed or unknown classes)."
        lines = [f"Generated {len(variants)} variants of {payload!r}:\n"]
        for i, v in enumerate(variants, 1):
            label = f"{v['mutation_class']}/{v['mutator']}"
            preview = v["variant"]
            if len(preview) > 200:
                preview = preview[:200] + f"...(+{len(v['variant']) - 200})"
            lines.append(f"  {i:>3d}. [{label}] {preview}")
        lines.append("\nFeed into fuzz_with_feedback(seed=...) or fuzz_parameter(payloads=...).")
        return "\n".join(lines)
