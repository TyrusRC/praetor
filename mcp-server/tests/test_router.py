import unittest

from praetor.tools.router import _rules


class TestRules(unittest.TestCase):
    def test_always_ask_covers_redteam_cloud_exploit(self):
        for t in ("run_network_tool", "run_prowler", "run_scout_suite",
                  "run_pacu", "msf_exploit", "scan_url"):
            self.assertIn(t, _rules.ALWAYS_ASK_TOOLS)

    def test_hard_deny_has_rule5_tokens(self):
        low = [t.lower() for t in _rules.HARD_DENY]
        for tok in ("drop table", "rm -rf", "delete from", "truncate", "shutdown"):
            self.assertIn(tok, low)

    def test_wordpress_rule_fires_wpscan(self):
        rule = next(r for r in _rules.ROUTING_TABLE if r["id"] == "tech_wordpress")
        sig = {"type": "tech", "value": "wordpress", "target": "https://x", "source": "t"}
        matched = rule["when"]([sig])
        self.assertEqual(len(matched), 1)
        actions = rule["fire"](matched[0])
        self.assertEqual(actions[0]["tool"], "run_wpscan")


from praetor.tools.router import _engine


class TestEngine(unittest.TestCase):
    def _sig(self, **kw):
        return {"type": kw["type"], "value": kw.get("value", ""),
                "target": kw.get("target", "https://x"), "source": "t"}

    def test_sql_error_is_auto_sqlmap_safe(self):
        out = _engine.match([self._sig(type="sql_error", value="id")])
        tools = [a["tool"] for a in out["auto"]]
        self.assertIn("run_sqlmap", tools)
        sm = next(a for a in out["auto"] if a["tool"] == "run_sqlmap")
        self.assertLessEqual(sm["args"].get("risk", 1), 1)

    def test_baseline_suppressed_when_covered(self):
        sig_p = self._sig(type="params_present", target="https://x/a")
        sig_c = {"type": "covered", "value": "", "target": "https://x/a", "source": "t"}
        out = _engine.match([sig_p, sig_c])
        self.assertNotIn("auto_probe", [a["tool"] for a in out["auto"]])
        out2 = _engine.match([sig_p])
        self.assertIn("auto_probe", [a["tool"] for a in out2["auto"]])

    def test_ad_and_cloud_forced_ask(self):
        out = _engine.match([self._sig(type="service", value="smb", target="10.0.0.1"),
                             self._sig(type="creds", value="cloud")])
        ask_tools = [a["tool"] for a in out["ask"]]
        self.assertIn("run_network_tool", ask_tools)
        self.assertIn("run_prowler", ask_tools)
        self.assertNotIn("run_network_tool", [a["tool"] for a in out["auto"]])

    def test_hard_denylisted_arg_dropped(self):
        out = _engine.match([self._sig(type="reflection", value="'; DROP TABLE users--",
                                       target="https://x")])
        self.assertTrue(any("DROP TABLE" in d.get("reason", "") for d in out["dropped"]))
        self.assertNotIn("run_dalfox", [a["tool"] for a in out["auto"]])


import os

from praetor.tools.router import _signals

RFIX = os.path.join(os.path.dirname(__file__), "fixtures", "router")


class TestSignals(unittest.TestCase):
    def test_collect_tech_from_profile(self):
        sigs = _signals.collect_signals("demo.local", base_dir=RFIX)
        techs = {s["value"].lower() for s in sigs if s["type"] == "tech"}
        self.assertIn("wordpress", techs)
        self.assertIn("php", techs)

    def test_collect_params_present_from_endpoints(self):
        sigs = _signals.collect_signals("demo.local", base_dir=RFIX)
        self.assertTrue(any(s["type"] == "params_present" for s in sigs))

    def test_missing_domain_returns_empty_not_crash(self):
        self.assertEqual(_signals.collect_signals("nope.invalid", base_dir=RFIX), [])

    def test_normalize_fills_keys(self):
        out = _signals.normalize_signals([{"type": "reflection", "value": "q"}])
        self.assertEqual(out[0]["type"], "reflection")
        self.assertIn("target", out[0])
        self.assertIn("source", out[0])


import asyncio

from praetor.tools.router import route


class TestRouteTool(unittest.TestCase):
    def test_route_merges_collected_and_supplied(self):
        out = asyncio.run(route.route_signals(
            domain="",
            signals=[{"type": "sql_error", "value": "id",
                      "target": "https://demo.local/api/orders?id=1"}],
        ))
        self.assertIn("auto", out)
        self.assertIn("ask", out)
        self.assertIn("dropped", out)
        self.assertIn("run_sqlmap", [a["tool"] for a in out["auto"]])
        self.assertIn("sql_error", out["signals_seen"])


class TestBatch2Rules(unittest.TestCase):
    def _sig(self, **kw):
        return {"type": kw["type"], "value": kw.get("value", ""),
                "target": kw.get("target", "https://x"), "source": "t"}

    def test_scan_candidate_targets_index_and_is_ask(self):
        from praetor.tools.router import _engine
        out = _engine.match([self._sig(type="scan_candidate", value=57)])
        ask = out["ask"]
        su = next((a for a in ask if a["tool"] == "scan_url"), None)
        self.assertIsNotNone(su)
        self.assertEqual(su["args"].get("index"), 57)
        self.assertNotIn("scan_url", [a["tool"] for a in out["auto"]])

    def test_azure_ad_creds_fire_azurehound_ask(self):
        from praetor.tools.router import _engine
        out = _engine.match([self._sig(type="creds", value="azure_ad", target="tenant-123")])
        self.assertIn("run_azurehound", [a["tool"] for a in out["ask"]])
        self.assertNotIn("run_azurehound", [a["tool"] for a in out["auto"]])
