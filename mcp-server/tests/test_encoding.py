"""Calibration tests for processing/encoding.py.

apply_operation drives every decode_encode / transform_chain / smart_decode
call. Calibration ensures aliases stay symmetric (b64e/b64d), the unknown-op
path raises cleanly, and padding tolerates whatever the operator passes in.

Run: uv run python -m unittest tests.test_encoding -v
"""

import unittest

from praetor.processing.encoding import (
    SHARED_OPS,
    apply_operation,
    pad_base64,
)


class Base64Tests(unittest.TestCase):
    def test_base64_encode_basic(self):
        self.assertEqual(apply_operation("hello", "base64_encode"), "aGVsbG8=")

    def test_base64_decode_basic(self):
        self.assertEqual(apply_operation("aGVsbG8=", "base64_decode"), "hello")

    def test_base64_alias_b64e(self):
        self.assertEqual(
            apply_operation("hello", "b64e"),
            apply_operation("hello", "base64_encode"),
        )

    def test_base64_alias_b64d(self):
        self.assertEqual(
            apply_operation("aGVsbG8=", "b64d"),
            apply_operation("aGVsbG8=", "base64_decode"),
        )

    def test_base64_decode_unpadded(self):
        # Operators paste b64 without trailing = constantly. Must self-pad.
        self.assertEqual(apply_operation("aGVsbG8", "base64_decode"), "hello")

    def test_base64_decode_garbage_replace(self):
        # errors='replace' means invalid bytes don't crash the chain.
        out = apply_operation("////", "base64_decode")
        self.assertIsInstance(out, str)

    def test_base64_roundtrip_ascii(self):
        for s in ("", "x", "hello world", "<script>"):
            enc = apply_operation(s, "b64e")
            dec = apply_operation(enc, "b64d")
            self.assertEqual(dec, s)


class PadBase64Tests(unittest.TestCase):
    def test_already_padded_is_idempotent(self):
        self.assertEqual(pad_base64("aGVsbG8="), "aGVsbG8=")

    def test_unpadded_one_short(self):
        # len % 4 == 3 -> add 1 =
        self.assertEqual(pad_base64("aGVsbG8"), "aGVsbG8=")

    def test_unpadded_two_short(self):
        # len % 4 == 2 -> add 2 =
        self.assertEqual(pad_base64("aGk"), "aGk=")  # 3 chars -> 1 pad

    def test_empty(self):
        self.assertEqual(pad_base64(""), "")


class UrlTests(unittest.TestCase):
    def test_url_encode_basic(self):
        self.assertEqual(apply_operation("hello world", "url_encode"),
                         "hello%20world")

    def test_url_encode_reserved(self):
        # safe="" should encode /, &, =, ?
        out = apply_operation("a=b&c=d", "url_encode")
        self.assertNotIn("=", out)
        self.assertNotIn("&", out)

    def test_url_decode_basic(self):
        self.assertEqual(apply_operation("hello%20world", "url_decode"),
                         "hello world")

    def test_double_url_encode(self):
        out = apply_operation(" ", "double_url_encode")
        # Single encode: %20.  Double encode: %2520.
        self.assertEqual(out, "%2520")

    def test_url_alias_urle(self):
        self.assertEqual(
            apply_operation("a b", "urle"),
            apply_operation("a b", "url_encode"),
        )

    def test_url_alias_urld(self):
        self.assertEqual(
            apply_operation("a%20b", "urld"),
            apply_operation("a%20b", "url_decode"),
        )

    def test_url_roundtrip(self):
        for s in ("hello", "a&b=c", "<script>alert(1)</script>"):
            self.assertEqual(
                apply_operation(apply_operation(s, "url_encode"), "url_decode"),
                s,
            )


class HtmlTests(unittest.TestCase):
    def test_html_encode_lt_gt(self):
        self.assertEqual(apply_operation("<a>", "html_encode"), "&lt;a&gt;")

    def test_html_encode_amp(self):
        self.assertIn("&amp;", apply_operation("a&b", "html_encode"))

    def test_html_decode_entities(self):
        self.assertEqual(apply_operation("&lt;a&gt;", "html_decode"), "<a>")

    def test_html_decode_numeric(self):
        self.assertEqual(apply_operation("&#60;a&#62;", "html_decode"), "<a>")

    def test_html_alias_htmle(self):
        self.assertEqual(
            apply_operation("<x>", "htmle"),
            apply_operation("<x>", "html_encode"),
        )

    def test_html_roundtrip(self):
        for s in ("plain", "<script>", "a & b"):
            self.assertEqual(
                apply_operation(apply_operation(s, "html_encode"), "html_decode"),
                s,
            )


class HexTests(unittest.TestCase):
    def test_hex_encode_ascii(self):
        self.assertEqual(apply_operation("ABC", "hex_encode"), "414243")

    def test_hex_decode_ascii(self):
        self.assertEqual(apply_operation("414243", "hex_decode"), "ABC")

    def test_ascii_hex_format(self):
        # \xNN form, lowercase, no separator.
        self.assertEqual(apply_operation("AB", "ascii_hex"), "\\x41\\x42")

    def test_hex_roundtrip(self):
        for s in ("abc", "<>?!@#"):
            self.assertEqual(
                apply_operation(apply_operation(s, "hex_encode"), "hex_decode"),
                s,
            )


class UnicodeTests(unittest.TestCase):
    def test_unicode_escape_newline(self):
        self.assertIn("\\n", apply_operation("a\nb", "unicode_escape"))

    def test_unicode_unescape_backslash_n(self):
        self.assertEqual(apply_operation("a\\nb", "unicode_unescape"), "a\nb")

    def test_unicode_roundtrip_ascii(self):
        for s in ("plain text", "tab\there", "quote\"x"):
            out = apply_operation(s, "unicode_escape")
            back = apply_operation(out, "unicode_unescape")
            self.assertEqual(back, s)


class SimpleTransformTests(unittest.TestCase):
    def test_reverse(self):
        self.assertEqual(apply_operation("abcd", "reverse"), "dcba")

    def test_reverse_empty(self):
        self.assertEqual(apply_operation("", "reverse"), "")

    def test_uppercase(self):
        self.assertEqual(apply_operation("abc", "uppercase"), "ABC")

    def test_lowercase(self):
        self.assertEqual(apply_operation("ABC", "lowercase"), "abc")


class UnknownOpTests(unittest.TestCase):
    def test_unknown_op_raises_valueerror(self):
        with self.assertRaises(ValueError) as ctx:
            apply_operation("x", "rot13")
        self.assertIn("Unknown operation", str(ctx.exception))

    def test_empty_op_raises(self):
        with self.assertRaises(ValueError):
            apply_operation("x", "")


class SharedOpsContractTests(unittest.TestCase):
    def test_all_shared_ops_callable_on_safe_input(self):
        # Every advertised op must accept a benign string and produce some str.
        for op in SHARED_OPS:
            if op == "hex_decode":
                src = "414243"
            elif op == "base64_decode":
                src = "aGVsbG8="
            elif op == "url_decode":
                src = "hello"
            elif op == "html_decode":
                src = "&lt;a&gt;"
            elif op == "unicode_unescape":
                src = "hello"
            else:
                src = "hello"
            out = apply_operation(src, op)
            self.assertIsInstance(out, str, op)


class ChainSanityTests(unittest.TestCase):
    """transform_chain in tools/transform.py composes apply_operation calls —
    verify the composition stays well-defined."""

    def test_url_then_base64_chain(self):
        s = "<script>"
        step1 = apply_operation(s, "url_encode")
        step2 = apply_operation(step1, "base64_encode")
        # Reverse
        step3 = apply_operation(step2, "base64_decode")
        step4 = apply_operation(step3, "url_decode")
        self.assertEqual(step4, s)

    def test_double_url_decode_undoes_double_url_encode(self):
        s = "hello world"
        enc = apply_operation(s, "double_url_encode")
        dec1 = apply_operation(enc, "url_decode")
        dec2 = apply_operation(dec1, "url_decode")
        self.assertEqual(dec2, s)


class XmlEntityTests(unittest.TestCase):
    def test_hex_entities_encodes_every_char(self):
        # Not just specials — keyword letters get encoded too (WAF bypass).
        self.assertEqual(apply_operation("AB", "hex_entities"), "&#x41;&#x42;")

    def test_dec_entities_encodes_every_char(self):
        self.assertEqual(apply_operation("AB", "dec_entities"), "&#65;&#66;")

    def test_hex_entities_hides_sql_keyword(self):
        enc = apply_operation("1 UNION SELECT", "hex_entities")
        self.assertNotIn("UNION", enc)
        self.assertNotIn("SELECT", enc)
        self.assertTrue(enc.startswith("&#x31;"))

    def test_html_decode_reverses_hex_entities(self):
        s = "1 UNION SELECT username || '~' || password FROM users"
        self.assertEqual(apply_operation(apply_operation(s, "hex_entities"), "html_decode"), s)

    def test_html_decode_reverses_dec_entities(self):
        s = "1 UNION SELECT NULL"
        self.assertEqual(apply_operation(apply_operation(s, "dec_entities"), "html_decode"), s)

    def test_both_entity_ops_registered(self):
        self.assertIn("hex_entities", SHARED_OPS)
        self.assertIn("dec_entities", SHARED_OPS)


class HashOpTests(unittest.TestCase):
    def test_md5_hex_digest(self):
        # Matches the value PortSwigger's stay-logged-in lab documents.
        self.assertEqual(
            apply_operation("peter", "md5"), "51dc30ddc473d43a6011e9ebba6ca770")

    def test_sha1_hex_digest(self):
        self.assertEqual(
            apply_operation("abc", "sha1"),
            "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_sha256_hex_digest(self):
        self.assertEqual(
            apply_operation("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_hashes_registered(self):
        for op in ("md5", "sha1", "sha256"):
            self.assertIn(op, SHARED_OPS)


class AffixOpTests(unittest.TestCase):
    def test_prefix_prepends(self):
        self.assertEqual(apply_operation("hash", "prefix:carlos:"), "carlos:hash")

    def test_suffix_appends(self):
        self.assertEqual(apply_operation("hash", "suffix:;end"), "hash;end")

    def test_prefix_value_preserves_case_and_colons(self):
        # Value after the first colon is verbatim — a "user:" token prefix
        # keeps its own colon and any capitals.
        self.assertEqual(apply_operation("x", "prefix:Admin:v2:"), "Admin:v2:x")

    def test_prefix_keyword_case_insensitive(self):
        self.assertEqual(apply_operation("x", "PREFIX:a"), "ax")

    def test_empty_suffix_is_noop(self):
        self.assertEqual(apply_operation("x", "suffix:"), "x")

    def test_affix_ops_registered(self):
        self.assertIn("prefix:<value>", SHARED_OPS)
        self.assertIn("suffix:<value>", SHARED_OPS)


class TokenBuildChainTests(unittest.TestCase):
    def test_build_stay_logged_in_cookie(self):
        # The full brute-force-a-stay-logged-in-cookie construction:
        # base64(username + ':' + md5(password)). Carlos / "mobilemail".
        step1 = apply_operation("mobilemail", "md5")
        step2 = apply_operation(step1, "prefix:carlos:")
        step3 = apply_operation(step2, "base64_encode")
        self.assertEqual(step3, "Y2FybG9zOmIzZThjZGQ5ZmY0NDI1OWZkNjdlODc5ZTU3OGNkOGY0")


if __name__ == "__main__":
    unittest.main()
