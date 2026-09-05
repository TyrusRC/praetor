"""Findings hub (Package 2: D remediation lifecycle + E multi-scanner import).

Pure-function + JSON coverage. No Burp client, no network.

- tools/hub/remediation.py::default_due_date / remediation_rollup
- tools/hub/importer.py::parse_nuclei / parse_nessus / merge_imported
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestRemediation(unittest.TestCase):
    def setUp(self):
        from praetor.tools.hub import remediation as r
        self.r = r

    def test_due_date_uses_severity_sla(self):
        # critical SLA is 7 days per default table
        due = self.r.default_due_date("2026-01-01T00:00:00+00:00", "critical")
        self.assertEqual(due[:10], "2026-01-08")

    def test_due_date_explicit_days_override(self):
        due = self.r.default_due_date("2026-01-01T00:00:00+00:00", "low", sla_days=3)
        self.assertEqual(due[:10], "2026-01-04")

    def test_rollup_counts_and_overdue(self):
        findings = [
            {"id": "f001", "severity": "high", "status": "confirmed",
             "remediation_status": "open", "due_date": "2026-01-01T00:00:00+00:00"},
            {"id": "f002", "severity": "low", "status": "confirmed",
             "remediation_status": "resolved", "created": "2026-01-01T00:00:00+00:00",
             "resolved_at": "2026-01-11T00:00:00+00:00"},
        ]
        roll = self.r.remediation_rollup(findings, now_iso="2026-02-01T00:00:00+00:00")
        self.assertEqual(roll["open"], 1)
        self.assertEqual(roll["resolved"], 1)
        self.assertEqual(roll["overdue"], 1)          # f001 due 2026-01-01, still open
        self.assertEqual(roll["mttr_days"], 10.0)     # f002: 10 days to resolve

    def test_rollup_resolved_is_not_overdue(self):
        findings = [
            {"id": "f003", "severity": "high", "status": "confirmed",
             "remediation_status": "resolved", "due_date": "2020-01-01T00:00:00+00:00",
             "created": "2019-12-01T00:00:00+00:00",
             "resolved_at": "2019-12-05T00:00:00+00:00"},
        ]
        roll = self.r.remediation_rollup(findings, now_iso="2026-02-01T00:00:00+00:00")
        self.assertEqual(roll["overdue"], 0)


_NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},'
    '"host":"https://app.example.com","matched-at":"https://app.example.com/api"}\n'
    '{"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},'
    '"host":"https://app.example.com","matched-at":"https://app.example.com"}\n'
)

_NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2><Report name="scan"><ReportHost name="10.0.0.5">
<ReportItem port="443" svc_name="www" severity="3" pluginName="SQL Injection">
<plugin_output>evidence here</plugin_output></ReportItem>
<ReportItem port="80" svc_name="www" severity="0" pluginName="HTTP Server Type">
</ReportItem>
</ReportHost></Report></NessusClientData_v2>"""

_NESSUS_XXE = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2><Report><ReportHost name="&xxe;">
<ReportItem port="443" severity="3" pluginName="x"/></ReportHost></Report></NessusClientData_v2>"""


class TestImporter(unittest.TestCase):
    def setUp(self):
        from praetor.tools.hub import importer as imp
        self.imp = imp

    def test_parse_nuclei_maps_severity_and_endpoint(self):
        rows = self.imp.parse_nuclei(_NUCLEI_JSONL)
        # info-severity row dropped; one real finding
        self.assertEqual(len(rows), 1)
        f = rows[0]
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["endpoint"], "https://app.example.com/api")
        self.assertEqual(f["source"], "nuclei")
        self.assertEqual(f["status"], "suspected")

    def test_parse_nessus_maps_and_drops_info(self):
        rows = self.imp.parse_nessus(_NESSUS_XML)
        self.assertEqual(len(rows), 1)             # severity 0 dropped
        f = rows[0]
        self.assertEqual(f["severity"], "high")    # nessus 3 -> high
        self.assertEqual(f["title"], "SQL Injection")
        self.assertIn("10.0.0.5", f["endpoint"])
        self.assertEqual(f["source"], "nessus")

    def test_parse_nessus_is_xxe_safe(self):
        # defusedxml must refuse entity expansion, not read /etc/passwd
        from defusedxml.common import EntitiesForbidden
        with self.assertRaises(EntitiesForbidden):
            self.imp.parse_nessus(_NESSUS_XXE)

    def test_merge_imported_dedupes(self):
        existing = []
        row = {"title": "SQLi", "vuln_type": "sqli", "endpoint": "/api",
               "parameter": "id", "severity": "high", "status": "suspected"}
        merged, created, updated = self.imp.merge_imported(existing, [row, dict(row)])
        self.assertEqual(created, 1)
        self.assertEqual(updated, 1)
        self.assertEqual(len(merged), 1)


if __name__ == "__main__":
    unittest.main()
