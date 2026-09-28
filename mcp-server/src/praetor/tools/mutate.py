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

import re
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


# ── Keyword-aware SQL/XSS bypasses (WAFs match whole keywords) ──────────────
_SQL_KEYWORDS = (
    "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "ORDER",
    "GROUP", "HAVING", "AND", "OR", "SLEEP", "BENCHMARK", "CONCAT", "SUBSTRING",
    "VERSION", "DATABASE", "INFORMATION_SCHEMA", "LIMIT", "JOIN", "NULL",
)


def _comment_inject_keywords(s: str) -> str:
    """Split SQL keywords with an inline comment: UNION -> UN/**/ION. Defeats a
    WAF that regexes whole keywords; the DB parser ignores /**/."""
    out = s
    for kw in _SQL_KEYWORDS:
        if len(kw) < 3:
            continue
        mid = len(kw) // 2
        broken = kw[:mid] + "/**/" + kw[mid:]
        out = re.sub(rf"(?i)\b{re.escape(kw)}\b", broken, out)
    return out


def _sql_versioned_comment(s: str) -> str:
    """Wrap SQL keywords in a MySQL versioned comment: UNION -> /*!50000UNION*/.
    Executes on MySQL, invisible to many signature WAFs."""
    out = s
    for kw in _SQL_KEYWORDS:
        out = re.sub(rf"(?i)\b{re.escape(kw)}\b", lambda m: f"/*!50000{m.group(0)}*/", out)
    return out


def _whitespace_sql_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def _whitespace_vtab(s: str) -> str:
    return s.replace(" ", "%0b")


def _whitespace_nbsp(s: str) -> str:
    return s.replace(" ", "%a0")


def _unicode_fullwidth(s: str) -> str:
    """Map ASCII ! .. ~ to fullwidth homoglyphs (U+FF01..FF5E). NFKC on the
    server normalises them back to ASCII AFTER the filter has passed them."""
    return "".join(
        chr(ord(c) - 0x21 + 0xFF01) if "!" <= c <= "~" else c for c in s
    )


def _overlong_utf8_path(s: str) -> str:
    """Overlong-UTF8 encode path-traversal bytes: '.' -> %c0%ae, '/' -> %c0%af.
    Legacy decoders accept them; path filters that match literal ../ miss them."""
    return s.replace(".", "%c0%ae").replace("/", "%c0%af").replace("\\", "%c0%5c")


def _html_entity_no_semicolon(s: str) -> str:
    """HTML hex entity WITHOUT the trailing semicolon (&#x3c) — many browsers
    still decode it, several XSS filters only strip the semicolon-terminated form."""
    specials = {"<": "&#x3c", ">": "&#x3e", '"': "&#x22", "'": "&#x27",
                "(": "&#x28", ")": "&#x29", "/": "&#x2f"}
    return "".join(specials.get(c, c) for c in s)


_SPECIAL = set("<>\"'()/ ;=&")


def _double_encode_special(s: str) -> str:
    """Double-URL-encode ONLY the filter-relevant chars — quieter than encoding
    the whole payload, and slips a decode-once gateway that re-inspects."""
    out = []
    for c in s:
        if c in _SPECIAL:
            out.append("%25" + format(ord(c), "02X"))
        else:
            out.append(c)
    return "".join(out)


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
    # Keyword-aware SQL bypasses (WAF matches whole keywords, DB parser doesn't).
    "comment_inject":   [_comment_inject_keywords],
    "sql_versioned":    [_sql_versioned_comment],
    "whitespace_sql":   [_whitespace_sql_comment, _whitespace_vtab, _whitespace_nbsp],
    # Unicode / encoding normalisation bypasses.
    "unicode_fullwidth": [_unicode_fullwidth],
    "overlong_utf8":    [_overlong_utf8_path],
    "html_no_semi":     [_html_entity_no_semicolon],
    "encoding_special": [_double_encode_special],
}


_DEFAULT_CLASSES = (
    "encoding_url",
    "encoding_double",
    "case_toggle",
    "case_mixed",
    "comment_sql",
    "comment_inject",
    "whitespace_sql",
    "null_byte",
    "whitespace_alt",
    "quote_rotate",
    "encoding_special",
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
        Nineteen mutation classes available — pass `classes=[]` (omit) for the
        recommended default subset, or list explicit classes to narrow.

        Args:
            payload: Seed payload to mutate.
            classes: Mutation classes. Default subset covers the most productive
                bypasses (url, double-url, case, sql-comment, keyword-inject,
                sql-whitespace, null, whitespace, quote rotation, special-encode).
                Available:
                encoding_url, encoding_double, encoding_unicode, encoding_html,
                encoding_special, case_toggle, case_mixed, comment_sql,
                comment_inject, sql_versioned, whitespace_alt, whitespace_sql,
                null_byte, crlf, quote_rotate, unicode_fullwidth, overlong_utf8,
                html_no_semi, length_pad.
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
