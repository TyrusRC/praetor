import unittest

from praetor.tools.evidence import _audit, _curate


class TestAnalyzeNoise(unittest.TestCase):
    H = [
        {"host": "t.com", "url": "https://t.com/app.js", "status": 200, "length": 5000},
        {"host": "t.com", "url": "https://t.com/a.css", "status": 200, "length": 900},
        {"host": "t.com", "url": "https://t.com/api/x?id=1", "status": 200, "length": 300},
        {"host": "t.com", "url": "https://t.com/api/x?id=2", "status": 200, "length": 300},
        {"host": "cdn.other.com", "url": "https://cdn.other.com/logo.png", "status": 200, "length": 20000},
    ]

    def test_static_and_scope_split(self):
        out = _audit.analyze_noise(self.H, scope_hosts={"t.com"})
        self.assertEqual(out["total"], 5)
        self.assertEqual(out["out_of_scope"], 1)
        self.assertGreaterEqual(out["static_assets"], 3)
        self.assertTrue(out["recommendations"])

    def test_duplicate_cluster_detected(self):
        out = _audit.analyze_noise(self.H, scope_hosts={"t.com"})
        clustered = [c for c in out["duplicate_clusters"] if c["path"].endswith("/api/x")]
        self.assertTrue(clustered and clustered[0]["count"] >= 2)


class TestApplyCuration(unittest.TestCase):
    def _findings(self):
        return {"findings": [{"id": "f001", "title": "x", "evidence": {}}]}

    def test_records_index_and_color(self):
        upd, msg = _curate.apply_curation(self._findings(), "f001", 42, "RED")
        ev = upd["findings"][0]["evidence"]
        self.assertEqual(ev["logger_index"], 42)
        self.assertEqual(ev["annotation_color"], "RED")
        self.assertTrue(ev["curated"])
        self.assertIn("f001", msg)

    def test_missing_id_errors_unchanged(self):
        upd, msg = _curate.apply_curation(self._findings(), "f999", 1, "RED")
        self.assertIn("not found", msg.lower())
        self.assertEqual(upd["findings"][0]["evidence"], {})
