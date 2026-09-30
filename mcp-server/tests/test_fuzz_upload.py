"""fuzz_upload — anomaly classifier + seed/mutator determinism.

Pure stdlib (unittest). Run with:
    uv run python -m unittest tests.test_fuzz_upload -v
"""

import random
import unittest

from praetor.tools.fuzzing import _seeds
from praetor.tools.fuzzing.upload import _classify


def _resp(status, length, hash_="h", elapsed=10, body="", index=1):
    return {"status": status, "length": length, "hash": hash_,
            "elapsed_ms": elapsed, "body": body, "index": index}


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        # Clean baseline: 200, small body, fast.
        self.base = {"status": 200, "length": 500, "response_hash": "b",
                     "elapsed_ms": 20, "body": "ok uploaded"}

    def test_500_is_anomaly(self):
        cls, _ = _classify(self.base, _resp(500, 500), budget_ms=1000)
        self.assertEqual(cls, "server_error")

    def test_200_vs_200_no_anomaly(self):
        cls, _ = _classify(self.base, _resp(200, 500), budget_ms=1000)
        self.assertEqual(cls, "")

    def test_clean_4xx_rejection_is_not_anomaly(self):
        # Malformed input SHOULD be refused — a 4xx is expected, not a finding.
        cls, _ = _classify(self.base, _resp(400, 480), budget_ms=1000)
        self.assertEqual(cls, "")

    def test_hang_flagged(self):
        cls, _ = _classify(self.base, _resp(200, 500, elapsed=5000), budget_ms=200)
        self.assertEqual(cls, "hang")

    def test_new_error_signature(self):
        r = _resp(200, 520, body="... Segmentation fault (core dumped) ...")
        cls, marker = _classify(self.base, r, budget_ms=1000)
        self.assertEqual(cls, "error_signature")
        self.assertIn("segmentation fault", marker)

    def test_size_divergence(self):
        cls, _ = _classify(self.base, _resp(200, 500 + 4096), budget_ms=1000)
        self.assertEqual(cls, "differential")


class SeedMutatorTests(unittest.TestCase):
    def test_seeds_valid_magic(self):
        self.assertEqual(_seeds.seed_for("png")[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(_seeds.seed_for("jpeg")[:2], b"\xff\xd8")
        self.assertEqual(_seeds.seed_for("gif")[:4], b"GIF8")
        self.assertEqual(_seeds.seed_for("pdf")[:4], b"%PDF")
        self.assertEqual(_seeds.seed_for("zip")[:4], b"PK\x03\x04")

    def test_mutate_deterministic_and_distinct(self):
        seed = _seeds.seed_for("png")
        m1 = _seeds.mutate(seed, "png", 40, random.Random(1337))
        m2 = _seeds.mutate(seed, "png", 40, random.Random(1337))
        self.assertEqual(m1, m2)                 # deterministic
        self.assertEqual(len(m1), 40)
        self.assertEqual(len(set(m1)), 40)       # distinct
        self.assertNotIn(seed, m1)               # never the unchanged seed

    def test_mutate_different_rng_differs(self):
        seed = _seeds.seed_for("png")
        m1 = _seeds.mutate(seed, "png", 40, random.Random(1))
        m2 = _seeds.mutate(seed, "png", 40, random.Random(2))
        self.assertNotEqual(m1, m2)


if __name__ == "__main__":
    unittest.main()
