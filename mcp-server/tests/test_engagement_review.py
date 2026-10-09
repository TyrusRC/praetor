"""import_engagement_review — the agent⇄human collaboration round-trip.

The human exports a review from the HTML hub; the agent imports it. A review
APPENDS a collab entry per finding and SURFACES a requested status change —
it never silently re-verdicts a finding (Rule 16b).
"""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools.intel import engagement


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class ImportEngagementReviewTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        engagement.register(self.mcp)
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        self.dom = "acme.tld"
        self.fdir = Path(self.tmp) / ".burp-intel" / self.dom
        self.fdir.mkdir(parents=True)
        (self.fdir / "findings.json").write_text(json.dumps({"findings": [
            {"id": "f001", "finding_id": "f001", "title": "SQLi", "severity": "high",
             "status": "confirmed"},
            {"id": "f002", "finding_id": "f002", "title": "IDOR", "severity": "medium",
             "status": "suspected"},
        ]}))

    def tearDown(self):
        os.chdir(self._cwd)

    def _call(self, _tool, **kw):
        return asyncio.run(self.mcp.tools[_tool](**kw))

    def _findings(self):
        data = json.loads((self.fdir / "findings.json").read_text())
        return {f["finding_id"]: f for f in data["findings"]}

    def test_appends_collab_without_reverdicting(self):
        review = json.dumps({
            "domain": self.dom, "reviewer": "alice",
            "notes": "Focus the retest on the cart flow.",
            "reviews": {
                "f001": {"status": "", "comment": "Great, confirmed — ship it."},
                "f002": {"status": "false_positive", "comment": "Returns my own data."},
                "f999": {"status": "", "comment": "ghost id"},
            },
        })
        out = self._call("import_engagement_review", domain=self.dom, review_json=review)

        f = self._findings()
        # collab appended on both real findings
        self.assertEqual(len(f["f001"]["collab"]), 1)
        self.assertEqual(f["f001"]["collab"][0]["reviewer"], "alice")
        self.assertIn("ship it", f["f001"]["collab"][0]["comment"])
        self.assertEqual(f["f002"]["collab"][0]["status_requested"], "false_positive")
        # statuses are NOT changed by the import (Rule 16b)
        self.assertEqual(f["f001"]["status"], "confirmed")
        self.assertEqual(f["f002"]["status"], "suspected")
        # requested change is surfaced, unknown id reported, notes appended
        self.assertIn("f002: suspected -> false_positive", out)
        self.assertIn("f999", out)
        self.assertIn("notes.md", out)
        notes = (self.fdir / "notes.md").read_text()
        self.assertIn("Human review", notes)
        self.assertIn("cart flow", notes)

    def test_empty_entries_skipped(self):
        review = json.dumps({"reviews": {"f001": {"status": "", "comment": "   "}}})
        out = self._call("import_engagement_review", domain=self.dom, review_json=review)
        self.assertNotIn("collab", (self.fdir / "findings.json").read_text())
        self.assertIn("0 finding", out)

    def test_bad_json_and_shape(self):
        self.assertIn("not valid JSON",
                      self._call("import_engagement_review", domain=self.dom, review_json="{nope"))
        self.assertIn("reviews",
                      self._call("import_engagement_review", domain=self.dom, review_json="{}"))

    def test_missing_file(self):
        out = self._call("import_engagement_review", domain=self.dom)
        self.assertIn("no review file", out)


if __name__ == "__main__":
    unittest.main()
