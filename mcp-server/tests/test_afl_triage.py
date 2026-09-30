"""AFL crash-triage rubric — sanitizer parser + exploitability classification.

Pure stdlib (unittest). No AFL binaries needed. Run with:
    uv run python -m unittest tests.test_afl_triage -v
"""

import tempfile
import unittest
from pathlib import Path

from praetor.tools.fuzzing.afl import (
    _parse_sanitizer, _classify_exploitability,
    _primitive_from_report, _refine_class,
)
from praetor.tools.fuzzing import _corpus, _seeds

# --- sample sanitizer reports -------------------------------------------------

_HEAP_WRITE = """\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018 at pc 0x0000004f1234 bp 0x7ffd sp 0x7ffd
WRITE of size 4 at 0x602000000018 thread T0
    #0 0x4f1234 in process_chunk parser.c:42:5
    #1 0x4f5678 in main harness.c:12:3
    #2 0x7f0011 in __libc_start_main
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:42:5 in process_chunk
"""

_HEAP_READ = """\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018 at pc 0x0000004f1234
READ of size 8 at 0x602000000018 thread T0
    #0 0x4f1234 in read_len parser.c:88:9
    #1 0x4f5678 in main harness.c:12:3
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:88:9 in read_len
"""

_NULL_SEGV = """\
==1234==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000004f9999 bp 0x sp 0x T0)
    #0 0x4f9999 in deref_null parser.c:5:3
    #1 0x4f5678 in main harness.c:12:3
SUMMARY: AddressSanitizer: SEGV parser.c:5:3 in deref_null
"""

_UAF = """\
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000004f2222
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x4f2222 in use_freed obj.c:33:7
    #1 0x4f5678 in main harness.c:12:3
SUMMARY: AddressSanitizer: heap-use-after-free obj.c:33:7 in use_freed
"""


class SanitizerParserTests(unittest.TestCase):
    def test_heap_write_parsed(self):
        info = _parse_sanitizer(_HEAP_WRITE)
        self.assertEqual(info["crash_type"], "heap-buffer-overflow")
        self.assertEqual(info["access"], "WRITE")
        self.assertEqual(info["frames"][0], "process_chunk")
        self.assertTrue(info["stack_hash"])          # a stable hash was produced
        self.assertIn("heap-buffer-overflow", info["excerpt"])

    def test_null_segv_addr_zero(self):
        info = _parse_sanitizer(_NULL_SEGV)
        self.assertEqual(info["crash_type"], "segv")
        self.assertEqual(info["addr"], 0)


class ExploitabilityRubricTests(unittest.TestCase):
    def test_heap_write_is_likely_exploitable(self):
        info = _parse_sanitizer(_HEAP_WRITE)
        self.assertEqual(_classify_exploitability(info), "LIKELY-EXPLOITABLE")

    def test_use_after_free_is_likely_exploitable(self):
        self.assertEqual(_classify_exploitability(_parse_sanitizer(_UAF)),
                         "LIKELY-EXPLOITABLE")

    def test_heap_read_is_medium(self):
        self.assertEqual(_classify_exploitability(_parse_sanitizer(_HEAP_READ)),
                         "MEDIUM")

    def test_null_deref_is_benign(self):
        self.assertEqual(_classify_exploitability(_parse_sanitizer(_NULL_SEGV)),
                         "BENIGN")


class StackHashDedupTests(unittest.TestCase):
    def test_same_top_frames_dedup_to_one(self):
        # Two crashes with identical crash type + top frames -> one unique.
        h1 = _parse_sanitizer(_HEAP_WRITE)["stack_hash"]
        h2 = _parse_sanitizer(_HEAP_WRITE)["stack_hash"]
        self.assertEqual(h1, h2)
        # A different crash site -> a different hash (not collapsed).
        self.assertNotEqual(h1, _parse_sanitizer(_UAF)["stack_hash"])

        crashes = [_HEAP_WRITE, _HEAP_WRITE, _UAF]
        seen, unique = set(), []
        for r in crashes:
            sh = _parse_sanitizer(r)["stack_hash"]
            if sh not in seen:
                seen.add(sh)
                unique.append(sh)
        self.assertEqual(len(unique), 2)   # two heap-writes collapse, UAF stays


class PrimitiveTests(unittest.TestCase):
    def test_heap_write_is_wxw(self):
        prim = _primitive_from_report(_parse_sanitizer(_HEAP_WRITE))
        self.assertEqual(prim["primitive"], "write-what-where")
        self.assertTrue(prim["wxw_potential"])
        self.assertEqual(prim["access_size"], 4)

    def test_heap_read_is_read_oob(self):
        prim = _primitive_from_report(_parse_sanitizer(_HEAP_READ))
        self.assertEqual(prim["primitive"], "read-oob")
        self.assertFalse(prim["wxw_potential"])

    def test_adjacent_write_downgrades_to_linear(self):
        # A small "located N bytes to the right" offset => linear, not wxw.
        report = _HEAP_WRITE + "\n0x602000000018 is located 0 bytes to the right of 8-byte region\n"
        prim = _primitive_from_report(_parse_sanitizer(report))
        self.assertEqual(prim["primitive"], "linear-write")
        self.assertFalse(prim["wxw_potential"])

    def test_null_deref_primitive_unknown(self):
        prim = _primitive_from_report(_parse_sanitizer(_NULL_SEGV))
        self.assertEqual(prim["primitive"], "unknown")


class RefineClassTests(unittest.TestCase):
    def test_write_zero_controlling_downgraded(self):
        prim = _primitive_from_report(_parse_sanitizer(_HEAP_WRITE))
        refined = _refine_class("LIKELY-EXPLOITABLE", prim,
                                {"controlling_bytes": 0, "sampled": 32}, None)
        self.assertTrue(refined.startswith("MEDIUM"), refined)

    def test_write_many_controlling_likely_exploitable(self):
        prim = _primitive_from_report(_parse_sanitizer(_HEAP_WRITE))
        refined = _refine_class("LIKELY-EXPLOITABLE", prim,
                                {"controlling_bytes": 20, "sampled": 32}, None)
        self.assertTrue(refined.startswith("LIKELY-EXPLOITABLE"), refined)

    def test_benign_never_upgraded(self):
        prim = _primitive_from_report(_parse_sanitizer(_NULL_SEGV))
        refined = _refine_class("BENIGN", prim,
                                {"controlling_bytes": 30, "sampled": 30}, "EXPLOITABLE")
        self.assertTrue(refined.startswith("BENIGN"), refined)


class CorpusDedupTests(unittest.TestCase):
    def setUp(self):
        self._prev = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        import os
        os.chdir(self._tmp.name)

    def tearDown(self):
        import os
        os.chdir(self._prev)
        self._tmp.cleanup()

    def test_seed_dedup_identical_inputs_one_file(self):
        payload = b"IDENTICAL-CORPUS-INPUT-BYTES-\x00\x01\x02"
        a = Path(self._tmp.name) / "a.png"
        b = Path(self._tmp.name) / "b.png"
        a.write_bytes(payload)
        b.write_bytes(payload)

        cdir = Path(_corpus.seed_corpus("corpus-test.local", "png", [str(a), str(b)]))
        matches = [p for p in cdir.iterdir()
                   if p.is_file() and p.read_bytes() == payload]
        self.assertEqual(len(matches), 1)            # two identical -> one file
        # the built-in valid PNG seed is also present (distinct content)
        self.assertIn(_seeds.seed_for("png"),
                      [p.read_bytes() for p in cdir.iterdir() if p.is_file()])

    def test_merge_back_dedup(self):
        dom, fmt = "corpus-test.local", "png"
        _corpus.seed_corpus(dom, fmt)                 # prime store with the builtin seed
        out = Path(self._tmp.name) / "out"
        queue = out / "default" / "queue"
        queue.mkdir(parents=True)
        dup = b"NEW-QUEUE-ENTRY-\xff\xfe"
        (queue / "id:000000").write_bytes(dup)
        (queue / "id:000001").write_bytes(dup)        # identical -> should dedup

        added = _corpus.merge_back(dom, fmt, str(out))
        self.assertEqual(added, 1)
        cdir = _corpus.corpus_dir(dom, fmt)
        self.assertEqual(sum(1 for p in cdir.iterdir()
                             if p.is_file() and p.read_bytes() == dup), 1)


if __name__ == "__main__":
    unittest.main()
