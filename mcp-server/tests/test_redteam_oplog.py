"""Red-team operator log, loot chain-of-custody, and Ghostwriter forwarding."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.redteam import _ghostwriter, _oplog


def _tool(name):
    return server.mcp._tool_manager._tools[name].fn


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()


class TestOperatorLog(_Base):
    async def test_record_action_auto_maps_attack(self):
        op = _oplog.record_action("box", "impacket-secretsdump",
                                  "secretsdump.py DOM/u:p@10.0.0.1",
                                  target="10.0.0.1", user_context="DOM\\u")
        self.assertTrue(op.startswith("op"))
        entries = _oplog.read_oplog("box")
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["technique"], "T1003")  # OS Credential Dumping
        self.assertEqual(e["tactic"], "Credential Access")
        self.assertIn("ttp:T1003", e["tags"])

    async def test_sequence_increments(self):
        _oplog.record_action("box", "nmap", "nmap x")
        _oplog.record_action("box", "netexec", "nxc smb x")
        ids = [e["id"] for e in _oplog.read_oplog("box")]
        self.assertEqual(ids, ["op0001", "op0002"])

    async def test_get_operator_log_views(self):
        _oplog.record_action("box", "responder", "responder -I eth0", target="10.0.0.0/24")
        tl = await _tool("get_operator_log")("box", "timeline")
        self.assertIn("responder", tl)
        atk = await _tool("get_operator_log")("box", "attack")
        self.assertIn("T1557.001", atk)  # LLMNR/NBT-NS poisoning


class TestLoot(_Base):
    async def test_loot_manifest_redacts_and_hashes(self):
        secret = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        row = _oplog.record_loot("box", "ntlm_hash", secret,
                                 source_host="DC01", obtained_via="secretsdump", oplog_id="op0001")
        # plaintext hash NOT in manifest; sha + shape only
        manifest = (self.root / ".burp-intel" / "box" / "network" / "loot.jsonl").read_text()
        self.assertNotIn(secret, manifest)
        self.assertIn(row["sha256"], manifest)
        self.assertIn("len", row["preview"])
        # artifact stored on disk
        self.assertTrue(Path(row["stored_path"]).exists())
        self.assertEqual(Path(row["stored_path"]).read_text(), secret)

    async def test_loot_view(self):
        _oplog.record_loot("box", "kerberos_tgs", "$krb5tgs$23$...", source_host="DC01")
        out = await _tool("get_operator_log")("box", "loot")
        self.assertIn("kerberos_tgs", out)
        self.assertIn("loot0001", out)


class TestGhostwriterMapping(unittest.TestCase):
    def test_finding_maps_to_reported_finding(self):
        # Findings go to Ghostwriter's reportedFinding (renders in the report),
        # not the oplog. Fields verified against reportedFinding_insert_input.
        obj = _ghostwriter.map_reported_finding({
            "id": "f001", "vuln_type": "sqli", "severity": "HIGH",
            "title": "SQLi", "endpoint": "https://t/x", "impact": "reads rows",
            "remediation": "parameterize", "evidence": {"logger_index": 42},
        }, report_id=7)
        self.assertEqual(obj["reportId"], 7)
        self.assertEqual(obj["severityId"], 4)          # HIGH -> 4
        self.assertEqual(obj["findingTypeId"], 4)       # https endpoint -> Web
        self.assertEqual(obj["impact"], "reads rows")
        self.assertEqual(obj["mitigation"], "parameterize")
        self.assertIn("logger_index=42", obj["references"])
        self.assertEqual(obj["extraFields"]["praetor_id"], "f001")

    def test_network_finding_maps_to_network_type(self):
        obj = _ghostwriter.map_reported_finding({
            "id": "f002", "vuln_type": "idor", "severity": "CRITICAL",
            "title": "DA", "endpoint": "10.10.11.20", "evidence": {"oplog_id": "op0006"},
        }, report_id=7)
        self.assertEqual(obj["severityId"], 5)          # CRITICAL -> 5
        self.assertEqual(obj["findingTypeId"], 1)       # non-URL -> Network
        self.assertIn("operator-log op0006", obj["references"])

    def test_oplog_entry_maps_attack_to_comments(self):
        with patch.object(_ghostwriter.config, "GHOSTWRITER_OPLOG_ID", 3):
            obj = _ghostwriter.map_oplog_entry({
                "id": "op0001", "tool": "nmap", "command": "nmap x",
                "technique": "T1046", "technique_name": "Network Service Discovery",
                "tags": ["ttp:T1046"], "start": "t", "end": "t",
            })
        self.assertEqual(obj["oplog"], 3)
        self.assertNotIn("tags", obj)
        self.assertIn("T1046", obj["comments"])
        self.assertEqual(obj["tool"], "nmap")
        self.assertEqual(obj["extraFields"]["tags"], ["ttp:T1046"])


class TestGhostwriterSync(_Base):
    async def test_unconfigured_is_a_clean_skip(self):
        # Isolate from any real .env that configures Ghostwriter globally.
        with patch.object(_ghostwriter.config, "GHOSTWRITER_URL", ""), \
             patch.object(_ghostwriter.config, "GHOSTWRITER_OPLOG_ID", 0):
            out = await _tool("sync_to_ghostwriter")("box", "all")
        self.assertIn("not configured", out)

    async def test_status_reports_unconfigured(self):
        from burpsuite_mcp.tools.redteam import _ghostwriter as gw
        with patch.object(gw.config, "GHOSTWRITER_URL", ""), \
             patch.object(gw.config, "GHOSTWRITER_OPLOG_ID", 0):
            out = await _tool("ghostwriter_status")("box")
        self.assertIn("NOT configured", out)

    async def test_configured_sync_pushes_and_dedupes(self):
        _oplog.record_action("box", "nmap", "nmap 10.0.0.1", target="10.0.0.1")
        _oplog.record_action("box", "netexec", "nxc smb 10.0.0.1", target="10.0.0.1")
        gql = AsyncMock(return_value={"data": {"insert_oplogEntry_one": {"id": 1}}})
        with patch.object(_ghostwriter.config, "GHOSTWRITER_URL", "http://gw"), \
             patch.object(_ghostwriter.config, "GHOSTWRITER_API_TOKEN", "tok"), \
             patch.object(_ghostwriter.config, "GHOSTWRITER_OPLOG_ID", 5), \
             patch.object(_ghostwriter, "_gql", gql):
            first = await _tool("sync_to_ghostwriter")("box", "oplog")
            self.assertIn("pushed: 2 oplog", first)
            self.assertEqual(gql.await_count, 2)
            # second sync: marker dedupes -> nothing pushed
            second = await _tool("sync_to_ghostwriter")("box", "oplog")
            self.assertIn("pushed: 0 oplog", second)
            self.assertEqual(gql.await_count, 2)

    async def test_sync_stops_on_first_error(self):
        _oplog.record_action("box", "nmap", "nmap 10.0.0.1")
        gql = AsyncMock(return_value={"error": "auth failed"})
        with patch.object(_ghostwriter.config, "GHOSTWRITER_URL", "http://gw"), \
             patch.object(_ghostwriter.config, "GHOSTWRITER_ADMIN_SECRET", "sek"), \
             patch.object(_ghostwriter.config, "GHOSTWRITER_OPLOG_ID", 5), \
             patch.object(_ghostwriter, "_gql", gql):
            out = await _tool("sync_to_ghostwriter")("box", "oplog")
        self.assertIn("auth failed", out)


if __name__ == "__main__":
    unittest.main()
