import os
import tempfile
import unittest

from praetor.tools import mantis_audit as m


def _sample():
    return {
        "schema": "mantis.audit/v1",
        "status": "ok",
        "totals": {"raw_findings": 3, "triaged": 2},
        "findings": [
            {"rule_id": "python.audit.dangerous-os-system", "severity": "ERROR",
             "confidence": "high", "path": "app/x.py", "start_line": 5, "end_line": 5,
             "message": "os.system with user input", "verdict": "TRUE", "cwe": "CWE-78"},
            {"rule_id": "generic.secrets.api-key", "severity": "WARNING",
             "path": "cfg.py", "start_line": 2, "message": "hardcoded key",
             "verdict": None, "cwe": None},
        ],
    }


class TestMantisSummary(unittest.TestCase):
    def test_summarise_sorts_and_lists(self):
        out = m._summarise(_sample(), "/repo")
        self.assertIn("mantis findings for /repo (2", out)
        self.assertIn("dangerous-os-system", out)
        self.assertIn("app/x.py:5", out)
        self.assertIn("CWE-78", out)
        self.assertIn("[TRUE]", out)
        self.assertLess(out.index("ERROR"), out.index("WARNING"))  # worst-first

    def test_summarise_empty(self):
        out = m._summarise(
            {"findings": [], "totals": {"raw_findings": 0, "triaged": 0}, "status": "ok"},
            "/repo")
        self.assertIn("no findings", out)

    def test_find_json_report_from_stdout(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "20260101-abc.json")
        with open(p, "w") as fh:
            fh.write("{}")
        self.assertEqual(m._find_json_report(f"[mantis] wrote {p}\n", d), p)

    def test_find_json_report_fallback_newest(self):
        d = tempfile.mkdtemp()
        runs = os.path.join(d, ".mantis", "runs")
        os.makedirs(runs)
        p = os.path.join(runs, "r.json")
        with open(p, "w") as fh:
            fh.write("{}")
        # stdout has no "wrote" line -> fall back to the newest run file
        self.assertEqual(m._find_json_report("no path here", d), p)


if __name__ == "__main__":
    unittest.main()
