"""Fuzz-upload seed/mutation/corpus logic — pure, no Burp.

Run with:
    uv run python -m unittest tests.test_fuzzing -v
"""

import random
import struct
import unittest

from praetor.tools.fuzzing._seeds import (
    seed_for,
    known_formats,
    detect_fmt,
    bitflip,
    byteflip,
    length_field_corrupt,
    integer_boundary,
    chunk_duplicate,
    chunk_truncate,
    token_inject,
    mutate,
    grammar_mutate,
    _token_offsets,
    _SEEDS,
)


class SeedFor(unittest.TestCase):

    def test_known_formats_returns_list(self):
        fmts = known_formats()
        self.assertIsInstance(fmts, list)
        self.assertIn("png", fmts)
        self.assertIn("pdf", fmts)

    def test_seed_for_each_known_format(self):
        for fmt in known_formats():
            s = seed_for(fmt)
            self.assertIsInstance(s, bytes)
            self.assertGreater(len(s), 0, f"empty seed for {fmt}")

    def test_seed_for_jpeg_aliases(self):
        self.assertEqual(seed_for("jpg"), seed_for("jpeg"))
        self.assertEqual(seed_for("jpe"), seed_for("jpeg"))
        self.assertEqual(seed_for(".jpeg"), seed_for("jpeg"))

    def test_seed_for_unknown_raises(self):
        with self.assertRaises(ValueError):
            seed_for("bmp")


class DetectFmt(unittest.TestCase):

    def test_detect_from_magic_bytes(self):
        for fmt in ("png", "jpeg", "gif", "webp", "pdf", "zip", "svg"):
            self.assertEqual(detect_fmt(_SEEDS[fmt]), fmt,
                             f"magic detection failed for {fmt}")

    def test_detect_from_filename(self):
        self.assertEqual(detect_fmt("photo.jpg"), "jpeg")
        self.assertEqual(detect_fmt("photo.jpeg"), "jpeg")
        self.assertEqual(detect_fmt("doc.pdf"), "pdf")
        self.assertEqual(detect_fmt("image.png"), "png")

    def test_detect_unknown_returns_empty(self):
        self.assertEqual(detect_fmt(b"\x00\x00\x00"), "")
        self.assertEqual(detect_fmt("file.bmp"), "")


class Mutators(unittest.TestCase):

    def setUp(self):
        self.rng = random.Random(42)
        self.png = seed_for("png")

    def test_bitflip_changes_one_bit(self):
        result = bitflip(self.png, self.rng, "png")
        self.assertEqual(len(result), len(self.png))
        diffs = sum(a != b for a, b in zip(result, self.png))
        self.assertEqual(diffs, 1, "bitflip should change exactly 1 byte")

    def test_byteflip_changes_one_byte(self):
        result = byteflip(self.png, self.rng, "png")
        self.assertEqual(len(result), len(self.png))
        diffs = sum(a != b for a, b in zip(result, self.png))
        self.assertEqual(diffs, 1)

    def test_length_field_corrupt_keeps_length(self):
        result = length_field_corrupt(self.png, self.rng, "png")
        self.assertEqual(len(result), len(self.png))

    def test_integer_boundary_keeps_length(self):
        result = integer_boundary(self.png, self.rng, "png")
        self.assertEqual(len(result), len(self.png))

    def test_chunk_duplicate_grows(self):
        result = chunk_duplicate(self.png, self.rng, "png")
        self.assertGreater(len(result), len(self.png))

    def test_chunk_truncate_shrinks_or_same(self):
        result = chunk_truncate(self.png, self.rng, "png")
        self.assertLessEqual(len(result), len(self.png))

    def test_token_inject_grows(self):
        result = token_inject(self.png, self.rng, "png")
        self.assertGreater(len(result), len(self.png))

    def test_empty_seed_passthrough(self):
        self.assertEqual(bitflip(b"", self.rng), b"")
        self.assertEqual(byteflip(b"", self.rng), b"")


class MutateTests(unittest.TestCase):

    def test_mutate_count(self):
        png = seed_for("png")
        rng = random.Random(42)
        results = mutate(png, "png", 10, rng)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(isinstance(r, bytes) for r in results))

    def test_mutate_deterministic(self):
        png = seed_for("png")
        a = mutate(png, "png", 5, random.Random(99))
        b = mutate(png, "png", 5, random.Random(99))
        self.assertEqual(a, b, "same seed should produce identical mutations")

    def test_mutate_different_seeds_differ(self):
        png = seed_for("png")
        a = mutate(png, "png", 5, random.Random(1))
        b = mutate(png, "png", 5, random.Random(2))
        self.assertNotEqual(a, b)

    def test_grammar_mutate_returns_list(self):
        png = seed_for("png")
        rng = random.Random(42)
        results = grammar_mutate(png, "png", 5, rng)
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, bytes) for r in results))


class TokenOffsets(unittest.TestCase):

    def test_png_has_structural_tokens(self):
        png = seed_for("png")
        offs = _token_offsets(png, "png")
        self.assertGreater(len(offs), 0, "PNG seed should have IHDR/IDAT/IEND offsets")

    def test_unknown_format_empty(self):
        offs = _token_offsets(b"\x00" * 100, "unknown")
        self.assertEqual(offs, [])


if __name__ == "__main__":
    unittest.main()
