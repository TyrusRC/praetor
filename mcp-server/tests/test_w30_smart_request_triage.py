"""W30-c — smart_request_triage: captured request → attack plan."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from burpsuite_mcp.tools import smart_request_triage as srt


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


def _get_tool():
    stub, captured = _stub_mcp()
    srt.register(stub)
    return captured["smart_request_triage"]


def _fake_resp(**overrides):
    base = {
        "url": "https://app.test/api/users/1",
        "method": "GET",
        "status_code": 200,
        "request_headers": [
            {"name": "Authorization", "value": "Bearer xyz"},
            {"name": "Host", "value": "app.test"},
        ],
        "response_headers": [
            {"name": "Content-Type", "value": "application/json"},
        ],
        "request_body": "",
        "response_body": '{"id":1,"name":"alice"}',
    }
    base.update(overrides)
    return base


# ---------- Helpers ----------

class HelpersTest(unittest.TestCase):

    def test_hkv_list_form(self):
        h = srt._hkv([{"name": "Content-Type", "value": "text/html"}])
        self.assertEqual(h["content-type"], "text/html")

    def test_hkv_dict_form(self):
        h = srt._hkv({"Authorization": "Bearer x"})
        self.assertEqual(h["authorization"], "Bearer x")

    def test_hkv_string_form(self):
        h = srt._hkv("Content-Type: text/html\nServer: nginx")
        self.assertEqual(h["content-type"], "text/html")
        self.assertEqual(h["server"], "nginx")

    def test_parse_query(self):
        out = srt._parse_query("https://x.test/?a=1&b=2")
        self.assertEqual(out, ["a", "b"])

    def test_parse_form_body(self):
        out = srt._parse_form_body("u=alice&p=secret",
                                   "application/x-www-form-urlencoded")
        self.assertEqual(out, ["u", "p"])

    def test_scan_secrets_finds_aws_and_jwt(self):
        # Synthetic shape-matching strings (avoid scanner false positives).
        body = ('key="' + 'AKIA' + 'Y' * 16 + '"; '
                'tok="' + 'eyJ' + 'Y' * 20 + '.eyJ' + 'Y' * 20 + '.' + 'Y' * 20 + '"')
        out = srt._scan_secrets(body)
        types = {s["type"] for s in out}
        self.assertIn("aws_access_key", types)
        self.assertIn("jwt_token", types)


# ---------- Body classification ----------

class ClassifyBodyTest(unittest.TestCase):

    def test_html_with_form_detected(self):
        body = '<html><body><form action="/x"><input name="a"></form></body></html>'
        out = srt._classify_body(body, "text/html")
        self.assertTrue(out["has_forms"])
        self.assertIn("a", out["form_inputs"])

    def test_rsc_response_detected(self):
        out = srt._classify_body('0:["$","$L1",null,{}]', "text/x-component")
        self.assertTrue(out["rsc_response"])

    def test_sqli_error_marker(self):
        body = "You have an error in your SQL syntax near 'foo'"
        out = srt._classify_body(body, "text/html")
        self.assertEqual(out["error_class"], "sqli")

    def test_ssti_error_marker(self):
        body = "jinja2.exceptions.TemplateSyntaxError"
        out = srt._classify_body(body, "text/html")
        self.assertEqual(out["error_class"], "ssti")

    def test_rce_marker(self):
        body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        out = srt._classify_body(body, "text/plain")
        self.assertEqual(out["error_class"], "rce")

    def test_stack_trace_detected(self):
        body = "Traceback (most recent call last):\n  File ..."
        out = srt._classify_body(body, "text/plain")
        self.assertTrue(out["stack_trace"])


# ---------- Synthesiser ----------

def _base_triage(**overrides):
    base = {
        "index": 7,
        "url": "https://app.test/api/users/1",
        "method": "GET",
        "status_code": 200,
        "content_type": "application/json",
        "request_params": {"query": [], "body": [], "cookies": []},
        "request_headers": [],
        "response_headers": [],
        "has_auth_header": False,
        "tech_hints": [],
        "response_size": 100,
        "response_signals": {
            "has_forms": False, "form_inputs": [],
            "stack_trace": False, "error_class": None,
            "rsc_response": False, "graphql_response": False,
            "secrets": [],
        },
    }
    for k, v in overrides.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            base[k].update(v)
        else:
            base[k] = v
    return base


class SynthesiserTest(unittest.TestCase):

    def test_sql_error_routes_to_confirm_sqli(self):
        t = _base_triage(response_signals={"error_class": "sqli"})
        plan = srt._synthesise(t)
        sqli = [p for p in plan if p["vuln_class"] == "sqli"]
        self.assertEqual(len(sqli), 1)
        self.assertEqual(sqli[0]["priority"], 0)
        self.assertIn("confirm_sqli", sqli[0]["suggested_call"])

    def test_rce_marker_routes_to_confirm_rce(self):
        t = _base_triage(response_signals={"error_class": "rce"})
        plan = srt._synthesise(t)
        rce = [p for p in plan if p["vuln_class"] == "rce"]
        self.assertEqual(len(rce), 1)
        self.assertIn("confirm_rce", rce[0]["suggested_call"])
        self.assertIn("command='id'", rce[0]["suggested_call"])

    def test_rsc_response_routes_to_react2shell(self):
        t = _base_triage(
            content_type="text/x-component",
            response_signals={"rsc_response": True},
        )
        plan = srt._synthesise(t)
        rsc = [p for p in plan if p["vuln_class"] == "react_server_components"]
        self.assertEqual(len(rsc), 1)
        self.assertIn("CVE-2025-55182", rsc[0]["suggested_call"])

    def test_js_response_routes_to_smart_js_analyze(self):
        t = _base_triage(
            url="https://app.test/main.js",
            content_type="application/javascript",
        )
        plan = srt._synthesise(t)
        js = [p for p in plan if p["vuln_class"] == "js_bundle_analysis"]
        self.assertEqual(len(js), 1)
        self.assertIn("smart_js_analyze", js[0]["suggested_call"])

    def test_html_with_forms_routes_to_csrf_and_dom(self):
        t = _base_triage(
            content_type="text/html",
            response_signals={"has_forms": True,
                              "form_inputs": ["user", "password"]},
        )
        plan = srt._synthesise(t)
        labels = [p["vuln_class"] for p in plan]
        self.assertIn("csrf", labels)
        self.assertIn("dom_xss", labels)

    def test_403_routes_to_auth_matrix(self):
        t = _base_triage(status_code=403)
        plan = srt._synthesise(t)
        auth = [p for p in plan if p["vuln_class"] == "auth_bypass"]
        self.assertEqual(len(auth), 1)
        self.assertIn("test_auth_matrix", auth[0]["suggested_call"])

    def test_negotiate_header_triggers_spnego_probe(self):
        t = _base_triage(
            status_code=401,
            response_headers=["content-type", "www-authenticate"],
        )
        plan = srt._synthesise(t)
        spnego = [p for p in plan if p["vuln_class"] == "enterprise_auth"]
        self.assertEqual(len(spnego), 1)
        self.assertIn("probe_kerberos_spnego_auth", spnego[0]["suggested_call"])

    def test_redirect_with_redirect_named_param(self):
        t = _base_triage(
            status_code=302,
            request_params={"query": ["redirect", "ignored"],
                            "body": [], "cookies": []},
        )
        plan = srt._synthesise(t)
        oredir = [p for p in plan if p["vuln_class"] == "open_redirect"]
        self.assertEqual(len(oredir), 1)
        self.assertIn("test_open_redirect", oredir[0]["suggested_call"])
        self.assertIn("'redirect'", oredir[0]["suggested_call"])

    def test_redirect_without_redirect_param_no_open_redirect_entry(self):
        t = _base_triage(
            status_code=302,
            request_params={"query": ["search"], "body": [], "cookies": []},
        )
        plan = srt._synthesise(t)
        oredir = [p for p in plan if p["vuln_class"] == "open_redirect"]
        self.assertEqual(oredir, [])

    def test_xml_post_routes_to_xxe(self):
        t = _base_triage(content_type="application/xml", method="POST")
        plan = srt._synthesise(t)
        xxe = [p for p in plan if p["vuln_class"] == "xxe"]
        self.assertEqual(len(xxe), 1)

    def test_authenticated_json_post_routes_to_auth_matrix_and_autoprobe(self):
        t = _base_triage(
            method="POST", has_auth_header=True,
        )
        plan = srt._synthesise(t)
        labels = [p["vuln_class"] for p in plan]
        self.assertIn("idor_bola", labels)
        self.assertIn("unknown", labels)  # auto_probe entry

    def test_debug_headers_emit_annotate(self):
        t = _base_triage(
            response_headers=["content-type", "x-powered-by", "server"],
        )
        plan = srt._synthesise(t)
        info = [p for p in plan if p["vuln_class"] == "info_disclosure"
                and "annotate_request" in p["suggested_call"]]
        self.assertGreaterEqual(len(info), 1)

    def test_secrets_in_body_emit_save_finding_with_chain_warning(self):
        t = _base_triage(response_signals={
            "secrets": [{"type": "aws_access_key", "match": "AKIA..."}],
        })
        plan = srt._synthesise(t)
        sec = [p for p in plan if p["vuln_class"] == "info_disclosure"
               and "save_finding" in p["suggested_call"]]
        self.assertEqual(len(sec), 1)
        self.assertIn("NEVER_SUBMIT", sec[0]["suggested_call"])

    def test_plan_priority_ordered_ascending(self):
        t = _base_triage(
            content_type="text/html",
            status_code=403,
            response_signals={"error_class": "sqli", "has_forms": True,
                              "secrets": [{"type": "jwt_token",
                                           "match": "eyJ..."}]},
        )
        plan = srt._synthesise(t)
        priorities = [p["priority"] for p in plan]
        self.assertEqual(priorities, sorted(priorities))


# ---------- Integration ----------

class IntegrationTest(unittest.TestCase):

    def test_full_pipeline_html_with_sql_error(self):
        tool = _get_tool()
        async def fake_get(path, params=None):
            return _fake_resp(
                url="https://app.test/search?q=foo",
                method="GET", status_code=500,
                response_headers=[{"name": "Content-Type", "value": "text/html"}],
                response_body=("<html><body>You have an error in your SQL "
                               "syntax near 'foo'</body></html>"),
            )
        with patch.object(srt.client, "get", side_effect=fake_get):
            out = asyncio.run(tool(index=42))
        self.assertEqual(out["status_code"], 500)
        self.assertEqual(out["response_signals"]["error_class"], "sqli")
        plan = out["attack_plan"]
        self.assertTrue(any(p["vuln_class"] == "sqli" for p in plan))

    def test_full_pipeline_rsc_response(self):
        tool = _get_tool()
        async def fake_get(path, params=None):
            return _fake_resp(
                url="https://app.test/dashboard", method="POST",
                response_headers=[
                    {"name": "Content-Type", "value": "text/x-component"}],
                response_body='0:["$","$L1",null,{"children":"x"}]\n',
            )
        with patch.object(srt.client, "get", side_effect=fake_get):
            out = asyncio.run(tool(index=11))
        self.assertTrue(out["response_signals"]["rsc_response"])
        self.assertTrue(any(p["vuln_class"] == "react_server_components"
                            for p in out["attack_plan"]))

    def test_negative_index_rejected(self):
        tool = _get_tool()
        out = asyncio.run(tool(index=-1))
        self.assertIn("error", out)

    def test_burp_error_propagates(self):
        tool = _get_tool()
        async def fake_get(path, params=None):
            return {"error": "index out of range"}
        with patch.object(srt.client, "get", side_effect=fake_get):
            out = asyncio.run(tool(index=99999))
        self.assertIn("error", out)


# ---------- Registration + routing ----------

class RegistrationAndRoutingTest(unittest.TestCase):

    def test_tool_registers(self):
        stub, captured = _stub_mcp()
        srt.register(stub)
        self.assertIn("smart_request_triage", captured)

    def test_pick_tool_routes_triage_request(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if "triage request" in keywords:
                match = tool_name
                break
        self.assertEqual(match, "smart_request_triage")

    def test_pick_tool_routes_what_to_do_next(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if "what to do next" in keywords:
                match = tool_name
                break
        self.assertEqual(match, "smart_request_triage")


if __name__ == "__main__":
    unittest.main()
