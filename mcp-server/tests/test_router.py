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
