"""prune_tool_output — safe disk-reclaim for raw tool-output dumps only.

Every guard here must be able to fail for a real reason:
- dry-run must never delete
- age/keep-recent gating must never prune a fresh or protected-recent file
- the ingestion guard must block pruning entirely when leads aren't ingested
- the path-containment guard must never let anything outside
  material/tool-output/ be touched, including via a symlink escape
"""

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from praetor.tools.prune_tool_output import prune_tool_output


def _touch(path: Path, content: bytes = b"x", age_days: float = 0.0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    if age_days:
        ts = time.time() - age_days * 86400
        os.utime(path, (ts, ts))


class PruneToolOutputTest(unittest.TestCase):
    DOMAIN = "example.com"

    def setUp(self):
        self._cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp(prefix="praetor-prune-")
        os.chdir(self.tmp)
        self.root = Path(self.tmp) / ".burp-intel" / self.DOMAIN
        self.tool_output = self.root / "material" / "tool-output"

    def tearDown(self):
        os.chdir(self._cwd)

    def _ingest(self):
        """Mark leads as ingested (non-empty endpoints.json + coverage.json)."""
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "endpoints.json").write_text(
            json.dumps({"endpoints": [{"url": "https://example.com/a"}]})
        )
        (self.root / "coverage.json").write_text(
            json.dumps({"knowledge_version": "abc", "entries": [{"tuple": "x"}]})
        )

    def _call(self, **kw):
        return asyncio.run(prune_tool_output(domain=self.DOMAIN, **kw))

    # -- dry-run ----------------------------------------------------------

    def test_dry_run_deletes_nothing_reports_candidates(self):
        self._ingest()
        old = self.tool_output / "ffuf-old.json"
        _touch(old, b"a" * 100, age_days=30)

        out = self._call(apply=False, max_age_days=7, keep_recent=0)

        self.assertTrue(out["dry_run"])
        self.assertTrue(old.exists(), "dry-run must not delete")
        names = [c["name"] for c in out["candidates"]]
        self.assertIn("ffuf-old.json", names)
        self.assertEqual(out["total_bytes"], 100)
        self.assertEqual(out["deleted"], [])

    # -- apply deletes only aged, non-keep_recent files --------------------

    def test_apply_deletes_only_aged_non_recent_files(self):
        self._ingest()
        old = self.tool_output / "nuclei-old.txt"
        _touch(old, b"y" * 50, age_days=30)

        out = self._call(apply=True, max_age_days=7, keep_recent=0)

        self.assertFalse(out["dry_run"])
        self.assertFalse(old.exists(), "aged file outside keep_recent must be deleted")
        self.assertIn("nuclei-old.txt", out["deleted"])

    # -- fresh file is protected by age -------------------------------------

    def test_fresh_file_not_pruned(self):
        self._ingest()
        fresh = self.tool_output / "katana-fresh.json"
        _touch(fresh, b"z", age_days=0.1)

        out = self._call(apply=True, max_age_days=7, keep_recent=0)

        self.assertTrue(fresh.exists(), "file younger than max_age_days must survive")
        self.assertNotIn("katana-fresh.json", out["deleted"])

    # -- keep_recent newest files are protected regardless of age ----------

    def test_keep_recent_protects_newest_files(self):
        self._ingest()
        paths = []
        for i in range(5):
            p = self.tool_output / f"gau-{i}.txt"
            # all old enough to be age-eligible, but written with increasing mtimes
            _touch(p, b"w", age_days=30 - i)
            paths.append(p)
            time.sleep(0.01)

        out = self._call(apply=True, max_age_days=7, keep_recent=2)

        surviving = [p for p in paths if p.exists()]
        self.assertEqual(len(surviving), 2, "exactly keep_recent files must survive")
        # the two newest (smallest age_days -> gau-3, gau-4) must be among survivors
        surviving_names = {p.name for p in surviving}
        self.assertEqual(surviving_names, {"gau-3.txt", "gau-4.txt"})

    # -- ingestion guard -----------------------------------------------------

    def test_missing_endpoints_json_prunes_nothing(self):
        old = self.tool_output / "subfinder-old.txt"
        _touch(old, b"q", age_days=30)
        # no endpoints.json / coverage.json written at all

        out = self._call(apply=True, max_age_days=7, keep_recent=0)

        self.assertTrue(old.exists(), "ungated (no ingestion evidence) must prune nothing")
        self.assertIn("skipped_reason", out)
        self.assertEqual(out["candidates"], [])
        self.assertEqual(out["deleted"], [])

    def test_empty_endpoints_json_prunes_nothing(self):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "endpoints.json").write_text(json.dumps({"endpoints": []}))
        (self.root / "coverage.json").write_text(
            json.dumps({"knowledge_version": "abc", "entries": [{"tuple": "x"}]})
        )
        old = self.tool_output / "amass-old.txt"
        _touch(old, b"q", age_days=30)

        out = self._call(apply=True, max_age_days=7, keep_recent=0)

        self.assertTrue(old.exists(), "empty endpoints.json must block pruning entirely")
        self.assertIn("skipped_reason", out)

    # -- containment guard: only material/tool-output/ is ever touched -----

    def test_files_outside_tool_output_never_touched(self):
        self._ingest()

        findings = self.root / "findings.json"
        findings.write_text(json.dumps({"findings": [{"id": "f1"}]}))
        artifact = self.root / "artifacts" / "x.png"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"\x89PNG")

        # a symlink inside tool-output/ pointing OUTSIDE the tool-output tree
        outside_target = self.root / "outside-secret.txt"
        _touch(outside_target, b"secret", age_days=30)
        self.tool_output.mkdir(parents=True, exist_ok=True)
        symlink = self.tool_output / "escape-link.txt"
        try:
            symlink.symlink_to(outside_target)
        except OSError:
            self.skipTest("symlinks unsupported in this environment")
        # backdate the symlink target itself; the link's lstat mtime doesn't
        # matter since containment is what must exclude it, not age.
        os.utime(outside_target, (time.time() - 30 * 86400,) * 2)

        # a genuine in-scope aged candidate, so apply=True actually does work
        real_old = self.tool_output / "ffuf-real.json"
        _touch(real_old, b"r", age_days=30)

        out = self._call(apply=True, max_age_days=7, keep_recent=0)

        self.assertTrue(findings.exists())
        self.assertTrue(artifact.exists())
        self.assertTrue(outside_target.exists(), "symlink escape target must never be deleted")
        self.assertNotIn("escape-link.txt", out["deleted"])
        self.assertNotIn("outside-secret.txt", out["deleted"])
        # the real in-scope candidate must still be handled normally
        self.assertFalse(real_old.exists())
        self.assertIn("ffuf-real.json", out["deleted"])


if __name__ == "__main__":
    unittest.main()
