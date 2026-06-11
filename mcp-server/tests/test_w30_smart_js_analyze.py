"""W30-b — smart_js_analyze: JS bundle → fire-ready attack plan."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from burpsuite_mcp.tools import smart_js_analyze as sja


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
    sja.register(stub)
    return captured["smart_js_analyze"]


# ---------- Static analysis ----------

class ExtractionRegexTest(unittest.TestCase):

    def test_rsc_action_ids_extracted(self):
        js = '''
        var action1 = createServerReference("abcdef1234567890abcdef1234567890abcdef12", null, null);
        var action2 = createServerReference("0000111122223333444455556666777788889999", null, null);
        '''
        out = sja._analyze_body(js, "https://app/_next/static/chunks/app/page.js")
        ids = out["findings"]["rsc_action_ids"]
        self.assertEqual(len(ids), 2)
        self.assertIn("abcdef1234567890abcdef1234567890abcdef12", ids)
        self.assertIn("0000111122223333444455556666777788889999", ids)

    def test_endpoints_and_fetch_extracted(self):
        js = '''
        fetch("/api/v2/users/me");
        axios.post("/api/orders");
        const URL = "/graphql";
        $.ajax({url: "/api/legacy/login"});
        '''
        out = sja._analyze_body(js, "x.js")
        eps = out["findings"]["endpoints"]
        self.assertIn("/api/v2/users/me", eps)
        self.assertIn("/api/orders", eps)
        self.assertIn("/api/legacy/login", eps)

    def test_websocket_extracted(self):
        js = 'const ws = new WebSocket("wss://api.example.com/ws");'
        out = sja._analyze_body(js, "x.js")
        self.assertIn("wss://api.example.com/ws", out["findings"]["websocket_urls"])

    def test_graphql_endpoint_and_op_extracted(self):
        js = '''
        const URL = "/api/graphql";
        const Q = `query GetUser($id: ID!) { user(id: $id) { name } }`;
        const M = `mutation Login($u: String!) { login(u: $u) }`;
        '''
        out = sja._analyze_body(js, "x.js")
        self.assertIn("/api/graphql", out["findings"]["graphql_endpoints"])
        op_names = {o["name"] for o in out["findings"]["graphql_operations"]}
        self.assertIn("GetUser", op_names)
        self.assertIn("Login", op_names)

    def test_secrets_extracted(self):
        # Synthetic patterns assembled at runtime so secret scanners don't
        # flag this test file. They match the regexes by shape only.
        js = '\n'.join([
            'const k1 = "' + 'AKIA' + 'X' * 16 + '";',
            'const k2 = "' + 'AIza' + 'X' * 35 + '";',
            'const k3 = "' + 'sk_' + 'live_' + 'X' * 30 + '";',
            'const tok = "' + 'eyJ' + 'X' * 20 + '.eyJ' + 'X' * 20 + '.' + 'X' * 20 + '";',
        ])
        out = sja._analyze_body(js, "x.js")
        types = {s["type"] for s in out["findings"]["secrets"]}
        self.assertIn("aws_access_key", types)
        self.assertIn("google_api_key", types)
        self.assertIn("stripe_live_secret", types)
        self.assertIn("jwt", types)

    def test_dom_sinks_extracted(self):
        js = '''
        el.innerHTML = userInput;
        document.write(htmlBlob);
        eval(payload);
        setTimeout("alert(1)", 100);
        window.addEventListener("message", handler);
        const x = {dangerouslySetInnerHTML: {__html: userInput}};
        '''
        out = sja._analyze_body(js, "x.js")
        sinks = out["findings"]["dom_sinks"]
        for name in ("innerHTML", "document.write", "eval",
                     "setTimeout_string", "postMessage_recv",
                     "dangerouslySetInnerHTML"):
            self.assertIn(name, sinks, f"missing sink {name}")

    def test_sourcemap_extracted(self):
        js = 'console.log("hi");\n//# sourceMappingURL=main.js.map'
        out = sja._analyze_body(js, "x.js")
        self.assertIn("main.js.map", out["findings"]["sourcemaps"])

    def test_framework_detected(self):
        js = '__NEXT_DATA__ = {props: {}}; var x = "next/dist/foo";'
        out = sja._analyze_body(js, "x.js")
        self.assertIn("nextjs", out["frameworks"])

    def test_empty_body_safe(self):
        out = sja._analyze_body("", "x.js")
        self.assertEqual(out["size"], 0)
        self.assertEqual(out["findings"], {})

    def test_big_body_truncated_flag(self):
        big = "/* " + ("x" * 2_100_000) + " */"
        out = sja._analyze_body(big, "big.js")
        self.assertTrue(out["truncated"])


# ---------- Synthesiser ----------

class SynthesiserTest(unittest.TestCase):

    def _fake_analysis(self, **findings):
        return {
            "source": "https://app/main.js", "size": 1000,
            "frameworks": ["nextjs"],
            "findings": {
                "endpoints": findings.get("endpoints", []),
                "websocket_urls": findings.get("websocket_urls", []),
                "graphql_endpoints": findings.get("graphql_endpoints", []),
                "graphql_operations": [],
                "rsc_action_ids": findings.get("rsc_action_ids", []),
                "auth_headers": [],
                "dom_sinks": findings.get("dom_sinks", {}),
                "secrets": findings.get("secrets", []),
                "sourcemaps": findings.get("sourcemaps", []),
            },
        }

    def test_rsc_actions_drive_react2shell_plan(self):
        a = self._fake_analysis(
            rsc_action_ids=["abcd1234abcd1234abcd1234abcd1234abcd1234"])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        rsc = [p for p in plan if p["vuln_class"] == "react_server_components"]
        self.assertEqual(len(rsc), 1)
        self.assertIn("probe_cve_with_variants", rsc[0]["suggested_tool"])
        self.assertIn("CVE-2025-55182", rsc[0]["suggested_call"])
        self.assertIn("abcd1234", rsc[0]["suggested_call"])
        # Priority 0 — comes first
        self.assertEqual(rsc[0]["priority"], 0)

    def test_graphql_endpoint_drives_test_graphql(self):
        a = self._fake_analysis(graphql_endpoints=["/api/graphql"])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        gql = [p for p in plan if p["vuln_class"] == "graphql"]
        self.assertEqual(len(gql), 1)
        self.assertIn("test_graphql", gql[0]["suggested_tool"])
        self.assertIn("test_introspection=True", gql[0]["suggested_call"])

    def test_websocket_drives_test_websocket(self):
        a = self._fake_analysis(websocket_urls=["wss://api.test/ws"])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        ws = [p for p in plan if p["vuln_class"] == "websocket"]
        self.assertEqual(len(ws), 1)
        self.assertIn("test_websocket", ws[0]["suggested_tool"])

    def test_dom_sinks_drive_test_dom_sinks(self):
        a = self._fake_analysis(dom_sinks={"innerHTML": ["userInput"]})
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        dom = [p for p in plan if p["vuln_class"] == "dom_xss"]
        self.assertEqual(len(dom), 1)
        self.assertIn("test_dom_sinks", dom[0]["suggested_tool"])
        self.assertIn("focus_sink='innerHTML'", dom[0]["suggested_call"])

    def test_postmessage_routes_to_dedicated_probe(self):
        a = self._fake_analysis(dom_sinks={"postMessage_recv": ["msg"]})
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        pm = [p for p in plan if p["vuln_class"] == "postmessage_xss"]
        self.assertEqual(len(pm), 1)
        self.assertIn("probe_postmessage_listeners", pm[0]["suggested_tool"])

    def test_endpoints_get_auto_probe(self):
        a = self._fake_analysis(endpoints=["/api/users", "/api/orders"])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        ap = [p for p in plan if p["suggested_tool"] == "auto_probe"]
        self.assertGreaterEqual(len(ap), 1)
        self.assertTrue(any("/api/users" in p["suggested_call"] for p in ap))

    def test_static_paths_excluded_from_endpoint_plan(self):
        a = self._fake_analysis(endpoints=[
            "/_next/static/chunks/main.js",
            "/static/css/app.css",
            "/__nextjs_original-stack-frame",
            "/api/users",
        ])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        ap = [p for p in plan if p["suggested_tool"] == "auto_probe"]
        for p in ap:
            self.assertNotIn("/_next/", p["suggested_call"])
            self.assertNotIn("/static/", p["suggested_call"])
        self.assertTrue(any("/api/users" in p["suggested_call"] for p in ap))

    def test_secrets_marked_chain_required(self):
        a = self._fake_analysis(secrets=[
            {"type": "aws_access_key", "match": "AKIA...", "offset": 0}
        ])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        sec = [p for p in plan if p["vuln_class"] == "info_disclosure"]
        self.assertEqual(len(sec), 1)
        self.assertIn("NEVER_SUBMIT", sec[0]["suggested_call"])
        self.assertIn("chain_with", sec[0]["suggested_call"])

    def test_priority_order_critical_first(self):
        a = self._fake_analysis(
            rsc_action_ids=["a" * 40],
            graphql_endpoints=["/graphql"],
            endpoints=["/api/x"],
            secrets=[{"type": "jwt", "match": "eyJ...", "offset": 0}],
        )
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        priorities = [p["priority"] for p in plan]
        self.assertEqual(priorities, sorted(priorities),
                         "plan must be priority-ordered ascending")
        # RSC must be first
        self.assertEqual(plan[0]["vuln_class"], "react_server_components")

    def test_canary_present_on_attack_entries(self):
        a = self._fake_analysis(rsc_action_ids=["a" * 40])
        plan = sja._synthesise_plan([a], "https://app.test", 10)
        for p in plan:
            if p["vuln_class"] in ("info_disclosure", "source_code_exposure"):
                continue
            self.assertTrue(p["canary"].startswith("PRAETOR-"))


# ---------- Tool integration ----------

class ToolIntegrationTest(unittest.TestCase):

    def test_url_mode_fetches_and_analyses(self):
        tool = _get_tool()
        js = '''
        var a = createServerReference("dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11", null, null);
        fetch("/api/graphql");
        const ws = new WebSocket("wss://x.test/socket");
        '''
        async def fake_post(path, json):
            return {
                "status_code": 200,
                "response_body": js,
                "response_headers": "",
                "proxy_index": 7,
                "url": json.get("url", ""),
            }
        with patch.object(sja.client, "post", side_effect=fake_post):
            result = asyncio.run(tool(
                url="https://app.test/_next/static/chunks/main.js",
                target_base_url="https://app.test",
                max_targets=5,
            ))
        self.assertIn("attack_plan", result)
        self.assertGreaterEqual(result["summary"]["rsc_action_ids"], 1)
        # Plan must START with the RSC entry
        self.assertEqual(result["attack_plan"][0]["vuln_class"],
                         "react_server_components")

    def test_index_and_url_mutex(self):
        tool = _get_tool()
        result = asyncio.run(tool(index=1, url="https://x.test/a.js"))
        self.assertIn("error", result)

    def test_no_input_returns_error(self):
        tool = _get_tool()
        result = asyncio.run(tool())
        self.assertIn("error", result)

    def test_batch_mode_caps_at_25(self):
        tool = _get_tool()
        calls = {"n": 0}
        async def fake_post(path, json):
            calls["n"] += 1
            return {"status_code": 200, "response_body": "",
                    "response_headers": "", "proxy_index": -1,
                    "url": json.get("url", "")}
        urls = [f"https://x.test/c{i}.js" for i in range(50)]
        with patch.object(sja.client, "post", side_effect=fake_post):
            asyncio.run(tool(urls=urls))
        self.assertLessEqual(calls["n"], 25, "batch must hard-cap at 25 URLs")

    def test_human_summary_contains_plan_lines(self):
        tool = _get_tool()
        js = 'createServerReference("ff" + "ff" * 19 + "ff", null, null);'  # 40 hex
        # Build a valid 40-hex action id directly
        js = 'createServerReference("' + ("f" * 40) + '", null, null);'
        async def fake_post(path, json):
            return {"status_code": 200, "response_body": js,
                    "response_headers": "", "proxy_index": 1,
                    "url": json.get("url", "")}
        with patch.object(sja.client, "post", side_effect=fake_post):
            result = asyncio.run(tool(
                url="https://app.test/a.js",
                target_base_url="https://app.test",
            ))
        self.assertIn("Attack plan", result["human_summary"])
        self.assertIn("probe_cve_with_variants", result["human_summary"])


# ---------- Registration + routing ----------

class RegistrationAndRoutingTest(unittest.TestCase):

    def test_tool_registers(self):
        stub, captured = _stub_mcp()
        sja.register(stub)
        self.assertIn("smart_js_analyze", captured)

    def test_pick_tool_routes_analyze_js(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if "analyze js" in keywords:
                match = tool_name
                break
        self.assertEqual(match, "smart_js_analyze")

    def test_pick_tool_routes_rsc_harvest(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if "rsc action id harvest" in keywords:
                match = tool_name
                break
        self.assertEqual(match, "smart_js_analyze")


if __name__ == "__main__":
    unittest.main()
