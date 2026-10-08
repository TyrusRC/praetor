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

_ASSAY_JSON = (
    '{"tool":"assay","scan_result":{"findings":['
    '{"type":"SQL Injection","severity":"Critical","url":"https://app.example.com/item",'
    '"parameter":"id","description":"error-based SQLi","cwe":["CWE-89"]},'
    '{"type":"Server Version Disclosure","severity":"Info","url":"https://app.example.com/"}'
    ']},"summary":{}}'
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

    def test_parse_assay_maps_and_drops_info(self):
        rows = self.imp.parse_assay(_ASSAY_JSON)
        # the Info-severity row is dropped; one real finding
        self.assertEqual(len(rows), 1)
        f = rows[0]
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["endpoint"], "https://app.example.com/item")
        self.assertEqual(f["parameter"], "id")
        self.assertEqual(f["source"], "assay")
        self.assertEqual(f["status"], "suspected")
        # vuln_type derives from the class name, not the description
        self.assertTrue(f["vuln_type"])

    def test_detect_format_assay(self):
        self.assertEqual(self.imp._detect_format("x.json", _ASSAY_JSON), "assay")

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

    def test_burp_rows_normalizes_and_drops_info(self):
        items = [
            {"name": "SQL injection", "severity": "High",
             "base_url": "https://x/a", "detail": "evidence"},
            {"name": "Info leak", "severity": "Information", "base_url": "https://x/b"},
        ]
        rows = self.imp._burp_rows(items)
        self.assertEqual(len(rows), 1)  # Information dropped
        self.assertEqual(rows[0]["source"], "burp")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["endpoint"], "https://x/a")

    def test_apply_rows_writes_store(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                rows = self.imp.parse_assay(_ASSAY_JSON)   # one real finding
                res = self.imp._apply_rows("t.com", rows)
                self.assertEqual(res["created"], 1)
                import json as _json
                stored = _json.loads(
                    open(os.path.join(d, ".burp-intel", "t.com", "findings.json")).read())
                self.assertEqual(len(stored["findings"]), 1)
                self.assertTrue(stored["findings"][0]["id"].startswith("f"))
            finally:
                os.chdir(cwd)

    def test_merge_imported_dedupes(self):
        existing = []
        row = {"title": "SQLi", "vuln_type": "sqli", "endpoint": "/api",
               "parameter": "id", "severity": "high", "status": "suspected"}
        merged, created, updated = self.imp.merge_imported(existing, [row, dict(row)])
        self.assertEqual(created, 1)
        self.assertEqual(updated, 1)
        self.assertEqual(len(merged), 1)


_BURP_XML = """<issues burpVersion="2024.1">
<issue><name>SQL injection</name><host ip="1.2.3.4">http://ex.com</host>
<path><![CDATA[/login]]></path><severity>High</severity>
<issueDetail>id param</issueDetail></issue>
<issue><name>Info leak</name><host>http://ex.com</host><path>/x</path>
<severity>Information</severity></issue></issues>"""

_OPENVAS_XML = """<report><results>
<result><name>OpenSSL flaw</name><host>10.0.0.5</host><port>443/tcp</port>
<severity>7.5</severity><threat>High</threat><description>vuln</description></result>
<result><name>Log line</name><host>10.0.0.5</host><severity>0.0</severity>
<threat>Log</threat></result></results></report>"""

_ZAP_JSON = ('{"site":[{"@name":"http://ex.com","alerts":['
             '{"riskcode":"3","alert":"XSS","desc":"reflected",'
             '"instances":[{"uri":"http://ex.com/q","param":"q"}]},'
             '{"riskcode":"0","alert":"Info","instances":[]}]}]}')


class TestImporterExtraParsers(unittest.TestCase):
    def setUp(self):
        from praetor.tools.hub import importer as imp
        self.imp = imp

    def test_parse_burp_drops_information(self):
        rows = self.imp.parse_burp_xml(_BURP_XML)
        self.assertEqual(len(rows), 1)              # 'Information' dropped
        f = rows[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["endpoint"], "http://ex.com/login")
        self.assertEqual(f["source"], "burp")

    def test_parse_openvas_cvss_band_and_drop_log(self):
        rows = self.imp.parse_openvas(_OPENVAS_XML)
        self.assertEqual(len(rows), 1)              # 0.0/Log dropped
        f = rows[0]
        self.assertEqual(f["severity"], "high")     # 7.5 -> high
        self.assertEqual(f["endpoint"], "10.0.0.5:443/tcp")

    def test_parse_zap_riskcode_and_param(self):
        rows = self.imp.parse_zap(_ZAP_JSON)
        self.assertEqual(len(rows), 1)              # riskcode 0 dropped
        f = rows[0]
        self.assertEqual(f["severity"], "high")     # riskcode 3 -> high
        self.assertEqual(f["parameter"], "q")
        self.assertEqual(f["endpoint"], "http://ex.com/q")

    def test_detect_format(self):
        self.assertEqual(self.imp._detect_format("x.xml", _BURP_XML), "burp")
        self.assertEqual(self.imp._detect_format("x.xml", _OPENVAS_XML), "openvas")
        self.assertEqual(self.imp._detect_format("x.json", _ZAP_JSON), "zap")


class TestTrackerAndEgress(unittest.TestCase):
    _F = {"id": "f001", "title": "SQLi", "severity": "high",
          "endpoint": "http://ex.com/login", "parameter": "id",
          "vuln_type": "sqli", "cwe": "CWE-89", "cvss4_vector": "CVSS:4.0/AV:N",
          "impact": "DB read", "remediation": "params", "status": "confirmed"}

    def test_issue_body_has_sections(self):
        from praetor.tools.hub.tracker import _issue_from_finding
        title, body = _issue_from_finding(self._F)
        self.assertTrue(title.startswith("[HIGH]"))
        self.assertIn("## Impact", body)
        self.assertIn("## Remediation", body)

    def test_cef_line_shape(self):
        from praetor.tools.hub.egress import _cef_line
        line = _cef_line(self._F, "ex.com")
        self.assertTrue(line.startswith("CEF:0|Praetor|Praetor|1.0|sqli|SQLi|8|"))
        self.assertIn("cs2=f001", line)


if __name__ == "__main__":
    unittest.main()
