"""AFL crash-triage rubric — sanitizer parser + exploitability classification.

Pure stdlib (unittest). No AFL binaries needed. Run with:
    uv run python -m unittest tests.test_afl_triage -v
"""

import unittest

from praetor.tools.fuzzing.afl import _parse_sanitizer, _classify_exploitability

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


if __name__ == "__main__":
    unittest.main()
