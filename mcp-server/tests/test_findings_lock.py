"""findings.json read-modify-write must not lose updates under concurrency.

save_finding (and the other mutators) load findings.json, append an entry, and
write it back as three separate steps. The atomic write prevents a torn file
but not a lost update: two agents load the same base, each append a different
finding, and the second write drops the first. _findings_lock serialises the
whole load+mutate+write so every concurrent append survives.
"""

import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from burpsuite_mcp.tools.notes._helpers import (
    _findings_lock,
    _load_findings_file,
    _write_findings_file,
)


class TestFindingsLock(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "d" / "findings.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_findings_file(self.path, {"findings": []})

    def tearDown(self):
        self._tmp.cleanup()

    def _append_locked(self, fid: str, barrier: threading.Barrier):
        # Line every thread up on the same base read to force the interleave
        # the lock has to defeat.
        barrier.wait()
        with _findings_lock(self.path):
            store = _load_findings_file(self.path)
            store["findings"].append({"id": fid})
            _write_findings_file(self.path, store)

    def test_concurrent_appends_all_survive(self):
        n = 24
        barrier = threading.Barrier(n)
        threads = [
            threading.Thread(target=self._append_locked, args=(f"f{i:03d}", barrier))
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        saved = json.loads(self.path.read_text())["findings"]
        ids = sorted(f["id"] for f in saved)
        self.assertEqual(len(ids), n, f"lost updates: only {len(ids)}/{n} survived")
        self.assertEqual(ids, [f"f{i:03d}" for i in range(n)])

    def test_lock_is_reentrant_across_sequential_use(self):
        # Acquiring, releasing, and re-acquiring in the same thread must not
        # deadlock (fresh fd per acquire).
        for i in range(3):
            with _findings_lock(self.path):
                store = _load_findings_file(self.path)
                store["findings"].append({"id": f"s{i}"})
                _write_findings_file(self.path, store)
        saved = json.loads(self.path.read_text())["findings"]
        self.assertEqual(len(saved), 3)


if __name__ == "__main__":
    unittest.main()
