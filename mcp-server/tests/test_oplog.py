"""Operation ledger: the record the model does not write.

The ledger exists so a claim ("I sent that", "see entry 118") can be checked
against something authored by the tool layer. These tests cover the properties
that make it trustworthy: it records real sends, it refuses to grow without
bound, it never archives credentials, and it stays quiet about traffic that
proves nothing.
"""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from burpsuite_mcp.tools.oplog import _store, _verify


class _TempLedger(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._patch = mock.patch.object(
            _store, "oplog_path", lambda: self.root / ".burp-intel" / "_oplog.jsonl"
        )
        self._patch.start()
        _store._SEQ = 0

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def path(self):
        return self.root / ".burp-intel" / "_oplog.jsonl"


class TestEvidentiaryFilter(_TempLedger):
    def test_target_send_is_recorded(self):
        self.assertTrue(_store.is_evidentiary({"url": "http://t/x"}))

    def test_reading_burp_state_is_not_recorded(self):
        self.assertFalse(_store.is_evidentiary({"api": "GET /api/proxy/history"}))
        self.assertFalse(_store.is_evidentiary({"api": "GET /api/scope"}))

    def test_claims_are_recorded_even_without_a_url(self):
        """Annotations and findings assert something; they need a ledger line."""
        self.assertTrue(_store.is_evidentiary({"api": "POST /api/annotations/set"}))
        self.assertTrue(_store.is_evidentiary({"api": "POST /api/notes/findings"}))

    def test_errors_are_always_recorded(self):
        self.assertTrue(
            _store.is_evidentiary({"api": "GET /api/scope", "outcome": "error"})
        )

    def test_filtered_operations_write_nothing(self):
        _store.record({"api": "GET /api/proxy/history", "outcome": "ok"})
        self.assertFalse(self.path().exists())


class TestRedaction(_TempLedger):
    def test_credential_query_values_are_stripped_but_names_kept(self):
        got = _store.redact_url("http://h/p?id=1&token=eyJhbGciOi.SECRET&q=x")
        self.assertIn("token=<redacted>", got)
        self.assertNotIn("SECRET", got)
        self.assertIn("id=1", got)
        self.assertIn("q=x", got)

    def test_payload_bearing_params_survive_intact(self):
        """Test input is the point of the ledger — it must not be scrubbed."""
        got = _store.redact_url("http://h/s?id=1 and 1=2")
        self.assertIn("1 and 1=2", got)

    def test_recorded_url_is_redacted_on_disk(self):
        _store.record({"url": "http://h/p?password=hunter2", "api": "POST /api/http/curl"})
        raw = self.path().read_text()
        self.assertNotIn("hunter2", raw)

    def test_no_query_string_is_passed_through(self):
        self.assertEqual(_store.redact_url("http://h/p"), "http://h/p")

    def test_absurdly_long_url_is_capped(self):
        self.assertLessEqual(len(_store.redact_url("http://h/" + "a" * 5000)), 512)


class TestRoundTrip(_TempLedger):
    def test_short_keys_on_disk_expand_on_read(self):
        _store.record({"tool": "curl_request", "url": "http://h/p",
                       "api": "POST /api/http/curl", "status": 200})
        row = json.loads(self.path().read_text().strip())
        self.assertIn("n", row)                 # compact on disk
        self.assertNotIn("tool", row)
        got = _store.read_entries()[0]
        self.assertEqual(got["tool"], "curl_request")   # readable on the way out
        self.assertEqual(got["status"], 200)

    def test_line_stays_compact(self):
        _store.record({"tool": "curl_request", "url": "http://testasp.vulnweb.com/showforum.asp?id=1",
                       "api": "POST /api/http/curl", "method": "GET",
                       "status": 200, "bytes": 3113, "elapsed_ms": 412, "outcome": "ok"})
        self.assertLess(len(self.path().read_text()), 260)

    def test_sequence_increments(self):
        for i in range(3):
            _store.record({"url": f"http://h/{i}", "api": "POST /api/http/curl"})
        self.assertEqual([e["seq"] for e in _store.read_entries()], [1, 2, 3])

    def test_malformed_line_does_not_break_reads(self):
        _store.record({"url": "http://h/a", "api": "POST /api/http/curl"})
        with self.path().open("a") as fh:
            fh.write("{ not json\n")
        _store.record({"url": "http://h/b", "api": "POST /api/http/curl"})
        self.assertEqual(len(_store.read_entries()), 2)


class TestFilters(_TempLedger):
    def setUp(self):
        super().setUp()
        _store.record({"url": "http://a.tld/1", "host": "a.tld", "tool": "curl_request",
                       "api": "POST /api/http/curl", "status": 200, "outcome": "ok"})
        _store.record({"url": "http://b.tld/2", "host": "b.tld", "tool": "session_request",
                       "api": "POST /api/session/request", "status": 500, "outcome": "ok"})

    def test_filter_by_host(self):
        self.assertEqual(len(_store.read_entries(host="a.tld")), 1)

    def test_filter_by_tool(self):
        self.assertEqual(_store.read_entries(tool="session")[0]["host"], "b.tld")

    def test_filter_by_status(self):
        self.assertEqual(_store.read_entries(status=500)[0]["host"], "b.tld")

    def test_since_seq_tails(self):
        self.assertEqual(len(_store.read_entries(since_seq=1)), 1)


class TestRotation(_TempLedger):
    def test_rotation_caps_growth_and_keeps_history_readable(self):
        with mock.patch.object(_store, "_MAX_BYTES", 400):
            for i in range(40):
                _store.record({"url": f"http://h/{i}", "api": "POST /api/http/curl"})
        self.assertTrue(self.path().with_suffix(".1.jsonl").exists(),
                        "expected a rotated generation")
        self.assertLess(self.path().stat().st_size, 4000)
        # Entries from before the rotation are still reachable, in order.
        seqs = [e["seq"] for e in _store.read_entries()]
        self.assertEqual(seqs, sorted(seqs))


class TestDisableSwitch(_TempLedger):
    def test_env_off_writes_nothing(self):
        with mock.patch.dict(os.environ, {"PRAETOR_OPLOG": "off"}):
            _store.record({"url": "http://h/p", "api": "POST /api/http/curl"})
        self.assertFalse(self.path().exists())


class TestReconcile(_TempLedger):
    """reconcile() against a proxy-history response shaped like ProxyHandler's.

    The live defect: /api/proxy/history returns entries under "items", but
    reconcile read "history"/"entries" and so saw zero. Every real tool send
    came back UNBACKED — "do not cite as evidence" — the exact inversion of the
    ledger's purpose. These fixtures use the real key so that regression fails
    here instead of on a live target.
    """

    def _reconcile(self, history_response):
        async def run():
            with mock.patch.object(_verify.client, "get",
                                   mock.AsyncMock(return_value=history_response)):
                return await _verify.reconcile(host="t.tld")
        return asyncio.run(run())

    def test_send_in_items_is_matched_not_flagged_unbacked(self):
        _store.record({"url": "http://t.tld/a?id=1", "host": "t.tld", "method": "GET",
                       "status": 200, "tool": "session_request", "outcome": "ok"})
        res = self._reconcile({"items": [
            {"index": 7, "url": "http://t.tld/a?id=1", "status_code": 200},
        ]})
        self.assertEqual(res["burp_entries"], 1)
        self.assertEqual(res["matched"], 1)
        self.assertEqual(res["unmatched_operations"], [])
        self.assertEqual(res["matches"][0]["burp_index"], 7)

    def test_status_conflict_is_surfaced(self):
        _store.record({"url": "http://t.tld/a", "host": "t.tld", "method": "GET",
                       "status": 200, "tool": "curl_request", "outcome": "ok"})
        res = self._reconcile({"items": [
            {"index": 3, "url": "http://t.tld/a", "status_code": 500},
        ]})
        self.assertEqual(len(res["status_conflicts"]), 1)

    def test_genuinely_absent_send_is_unbacked(self):
        _store.record({"url": "http://t.tld/ghost", "host": "t.tld", "method": "GET",
                       "status": 200, "tool": "curl_request", "outcome": "ok"})
        res = self._reconcile({"items": []})
        self.assertEqual(len(res["unmatched_operations"]), 1)

    def test_unattributed_burp_traffic_is_reported(self):
        res = self._reconcile({"items": [
            {"index": 1, "url": "http://t.tld/browser-only", "status_code": 200},
        ]})
        self.assertEqual(len(res["unmatched_history"]), 1)


if __name__ == "__main__":
    unittest.main()
